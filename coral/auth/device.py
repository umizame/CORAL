"""OAuth 2.0 Device Authorization Grant — RFC 8628.

The flow:

    1. CLI POSTs to `<provider>/api/v1/devices/code` and receives:
       - device_code (server secret, kept by the CLI)
       - user_code  (short, human-readable; user enters it in the browser)
       - verification_url           (where the user opens the browser)
       - verification_url_complete? (optional convenience URL with the code baked in)
       - expires_in                 (seconds until the device_code expires)
       - interval                   (minimum seconds between token-poll calls)

    2. CLI prints the user_code + verification URL and starts polling
       `<provider>/api/v1/devices/token` every `interval` seconds.

    3. Token endpoint returns one of:
       - 200 with access_token / refresh_token / token_type / expires_in (success)
       - 400 { "error": "authorization_pending" }  — keep polling
       - 400 { "error": "slow_down" }              — increase interval by 5s
       - 400 { "error": "access_denied" }          — user rejected; AccessDeniedError
       - 400 { "error": "expired_token" }          — device_code expired; AuthorizationExpiredError
       - other 4xx/5xx                              — AuthError

This module is provider-agnostic: any compliant device-grant
implementation works. The optional `fetch_user_info()` helper hits a
conventional `/api/v1/users/me` endpoint for display in `coral whoami`.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# OAuth 2.0 grant-type URI for device flow (RFC 8628 §3.4).
DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

# Client identifier. Public clients in device-grant don't have a secret;
# this string is just an audit/UA hint for the provider. Reef + sister
# providers should accept any value (or pin it to `coral-cli`).
CLIENT_ID = "coral-cli"

# Conservative ceilings — the provider's own `interval` and `expires_in`
# take precedence; these guard against a malicious / broken provider
# pinning us at sub-second polls or telling us to wait an hour.
MIN_POLL_INTERVAL = 1.0
MAX_POLL_INTERVAL = 30.0
DEFAULT_TIMEOUT = 900  # 15 minutes — RFC 8628 default expires_in upper bound


class AuthError(Exception):
    """Anything wrong with the device-grant exchange that isn't user-driven."""


class AccessDeniedError(AuthError):
    """User explicitly declined the authorization on the provider page."""


class AuthorizationExpiredError(AuthError):
    """The device_code expired before the user completed authorization."""


@dataclass
class DeviceCodeResponse:
    """Decoded `/devices/code` response (step 1)."""

    device_code: str
    user_code: str
    verification_url: str
    verification_url_complete: str | None
    expires_in: int
    interval: float

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DeviceCodeResponse:
        # Accept both `verification_uri` (RFC spelling) and `verification_url`
        # (commonly used in the wild; e.g. Google's IdP) for robustness.
        verification_url = d.get("verification_uri") or d.get("verification_url")
        verification_url_complete = (
            d.get("verification_uri_complete") or d.get("verification_url_complete")
        )
        if not d.get("device_code") or not d.get("user_code") or not verification_url:
            raise AuthError(
                "provider returned an incomplete device-code response "
                "(expected device_code, user_code, verification_uri)"
            )
        raw_interval = d.get("interval", 5)
        try:
            interval = max(MIN_POLL_INTERVAL, min(MAX_POLL_INTERVAL, float(raw_interval)))
        except (TypeError, ValueError):
            interval = 5.0
        return cls(
            device_code=d["device_code"],
            user_code=d["user_code"],
            verification_url=verification_url,
            verification_url_complete=verification_url_complete,
            expires_in=int(d.get("expires_in", DEFAULT_TIMEOUT)),
            interval=interval,
        )


@dataclass
class _PollResult:
    """Decoded `/devices/token` response (step 3)."""

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int | None
    user: dict[str, Any] | None  # optional inline identity (saves a /users/me call)


def normalize_provider_url(url: str) -> str:
    """Strip trailing slashes + lowercase the host. Idempotent.

    `https://Reef.app/  ` → `https://reef.app`. Used as the key in the
    credentials file so `coral login https://reef.app/` and
    `coral login https://REEF.app` are the same provider.
    """
    url = url.strip()
    if not url:
        raise AuthError("provider URL is empty")
    if not url.startswith(("http://", "https://")):
        # Be friendly: assume https when scheme is omitted.
        url = "https://" + url
    parsed = urllib.parse.urlsplit(url)
    if not parsed.netloc:
        raise AuthError(f"invalid provider URL: {url!r}")
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def request_device_code(
    provider_url: str,
    *,
    client_id: str = CLIENT_ID,
    client: httpx.Client | None = None,
) -> DeviceCodeResponse:
    """Step 1: POST to `/api/v1/devices/code`."""
    provider_url = normalize_provider_url(provider_url)
    endpoint = f"{provider_url}/api/v1/devices/code"
    owns_client = client is None
    c = client or httpx.Client(timeout=30.0)
    try:
        resp = c.post(endpoint, data={"client_id": client_id})
    except httpx.HTTPError as e:
        raise AuthError(f"could not reach provider at {endpoint}: {e}") from e
    finally:
        if owns_client:
            c.close()
    if resp.status_code >= 400:
        raise AuthError(
            f"device-code request failed: HTTP {resp.status_code}: {resp.text[:200]}"
        )
    return DeviceCodeResponse.from_dict(resp.json())


def poll_for_token(
    provider_url: str,
    device_code: str,
    *,
    interval: float,
    expires_in: int,
    client_id: str = CLIENT_ID,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> _PollResult:
    """Step 3: poll `/api/v1/devices/token` until success or terminal error.

    `sleep` and `now` are injectable so tests can fast-forward without
    actually waiting. The default uses `time.monotonic` to be immune to
    wall-clock jumps (NTP corrections etc.) mid-poll.
    """
    provider_url = normalize_provider_url(provider_url)
    endpoint = f"{provider_url}/api/v1/devices/token"
    deadline = now() + expires_in
    owns_client = client is None
    c = client or httpx.Client(timeout=30.0)
    current_interval = interval
    try:
        while True:
            if now() >= deadline:
                raise AuthorizationExpiredError(
                    "device code expired before the user authorized it"
                )
            sleep(current_interval)
            try:
                resp = c.post(
                    endpoint,
                    data={
                        "grant_type": DEVICE_CODE_GRANT_TYPE,
                        "device_code": device_code,
                        "client_id": client_id,
                    },
                )
            except httpx.HTTPError as e:
                # Transient network errors — keep polling rather than aborting
                # the whole login. The deadline check at the top of the loop
                # bounds how long we'll keep trying.
                logger.debug("token-poll network error (will retry): %s", e)
                continue
            if resp.status_code == 200:
                body = resp.json()
                return _PollResult(
                    access_token=body["access_token"],
                    refresh_token=body.get("refresh_token"),
                    token_type=body.get("token_type", "Bearer"),
                    expires_in=body.get("expires_in"),
                    user=body.get("user"),
                )
            # RFC 8628 §3.5: errors come back as 400 with an OAuth-style body.
            try:
                err = resp.json().get("error", "")
            except Exception:
                err = ""
            if err == "authorization_pending":
                continue
            if err == "slow_down":
                current_interval = min(MAX_POLL_INTERVAL, current_interval + 5.0)
                continue
            if err == "access_denied":
                raise AccessDeniedError("authorization was denied by the user")
            if err == "expired_token":
                raise AuthorizationExpiredError("device code expired")
            raise AuthError(
                f"unexpected token-poll response "
                f"(HTTP {resp.status_code}, error={err!r}): {resp.text[:200]}"
            )
    finally:
        if owns_client:
            c.close()


def device_login(
    provider_url: str,
    *,
    on_user_code: Callable[[DeviceCodeResponse], None] | None = None,
    client_id: str = CLIENT_ID,
    client: httpx.Client | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> tuple[DeviceCodeResponse, _PollResult]:
    """Run the full device-grant exchange.

    `on_user_code` is called once after step 1 with the DeviceCodeResponse so
    the caller can show the user the code + verification URL (and optionally
    open a browser). If omitted, the caller is expected to display info
    separately — handy for tests that don't want stdout noise.
    """
    code_resp = request_device_code(
        provider_url, client_id=client_id, client=client
    )
    if on_user_code is not None:
        on_user_code(code_resp)
    poll_resp = poll_for_token(
        provider_url,
        code_resp.device_code,
        interval=code_resp.interval,
        expires_in=code_resp.expires_in,
        client_id=client_id,
        client=client,
        sleep=sleep,
        now=now,
    )
    return code_resp, poll_resp


def fetch_user_info(
    provider_url: str,
    access_token: str,
    *,
    client: httpx.Client | None = None,
) -> dict[str, Any] | None:
    """Best-effort GET `/api/v1/users/me`. Returns None on any failure.

    Skipping the body's identity is non-fatal — `coral whoami` will fall
    back to the bare access token if the provider doesn't expose this
    endpoint or it errors.
    """
    provider_url = normalize_provider_url(provider_url)
    endpoint = f"{provider_url}/api/v1/users/me"
    owns_client = client is None
    c = client or httpx.Client(timeout=15.0)
    try:
        resp = c.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
    except httpx.HTTPError as e:
        logger.debug("fetch_user_info failed: %s", e)
        return None
    finally:
        if owns_client:
            c.close()
    if resp.status_code != 200:
        return None
    try:
        return resp.json()
    except Exception:
        return None
