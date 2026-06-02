"""Device-grant flow tests using httpx.MockTransport.

We exercise the protocol-level behavior — happy path, the three RFC-8628
specific 400 errors (`authorization_pending`, `slow_down`, `access_denied`,
`expired_token`), and the `verification_uri` vs `verification_url`
spelling tolerance — without touching the network.

`sleep` and `now` are injected so the polling loop is instantaneous in
tests.
"""

from __future__ import annotations

import httpx
import pytest

from coral.auth.device import (
    DEVICE_CODE_GRANT_TYPE,
    AccessDeniedError,
    AuthError,
    AuthorizationExpiredError,
    device_login,
    normalize_provider_url,
    poll_for_token,
    request_device_code,
)

# ---------- normalize_provider_url ----------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://reef.app", "https://reef.app"),
        ("https://Reef.App/", "https://reef.app"),
        ("  https://reef.app/  ", "https://reef.app"),
        ("https://reef.app/some/path/", "https://reef.app/some/path"),
        ("reef.app", "https://reef.app"),  # bare host -> https
    ],
)
def test_normalize_provider_url(raw, expected):
    assert normalize_provider_url(raw) == expected


def test_normalize_provider_url_rejects_empty():
    with pytest.raises(AuthError):
        normalize_provider_url("")


def test_normalize_provider_url_rejects_bogus():
    with pytest.raises(AuthError):
        normalize_provider_url("https://")


# ---------- helpers ----------


def _fake_clock():
    """Return (now_fn, sleep_fn) where sleep advances now."""
    t = [0.0]

    def now() -> float:
        return t[0]

    def sleep(s: float) -> None:
        t[0] += s

    return now, sleep


def _client_from_handler(handler):
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport)


# ---------- request_device_code ----------


def test_request_device_code_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/v1/devices/code"
        body = dict(httpx.QueryParams(request.content.decode()))
        assert body == {"client_id": "coral-cli"}
        return httpx.Response(
            200,
            json={
                "device_code": "dev-secret",
                "user_code": "ABCD-1234",
                "verification_uri": "https://reef.app/device",
                "verification_uri_complete": "https://reef.app/device?code=ABCD-1234",
                "expires_in": 600,
                "interval": 3,
            },
        )

    with _client_from_handler(handler) as client:
        resp = request_device_code("https://reef.app", client=client)

    assert resp.device_code == "dev-secret"
    assert resp.user_code == "ABCD-1234"
    assert resp.verification_url == "https://reef.app/device"
    assert resp.verification_url_complete == "https://reef.app/device?code=ABCD-1234"
    assert resp.expires_in == 600
    assert resp.interval == 3.0


def test_request_device_code_accepts_url_spelling():
    """Some providers emit `verification_url` (Google convention)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "device_code": "d",
                "user_code": "U",
                "verification_url": "https://reef.app/device",
                "expires_in": 600,
                "interval": 5,
            },
        )

    with _client_from_handler(handler) as client:
        resp = request_device_code("https://reef.app", client=client)
    assert resp.verification_url == "https://reef.app/device"


def test_request_device_code_clamps_interval_too_small():
    def handler(_):
        return httpx.Response(
            200,
            json={
                "device_code": "d",
                "user_code": "U",
                "verification_uri": "https://reef.app/device",
                "expires_in": 60,
                "interval": 0,  # would peg us at zero-sleep
            },
        )

    with _client_from_handler(handler) as client:
        resp = request_device_code("https://reef.app", client=client)
    assert resp.interval >= 1.0


def test_request_device_code_500_raises():
    def handler(_):
        return httpx.Response(500, text="boom")

    with _client_from_handler(handler) as client, pytest.raises(AuthError):
        request_device_code("https://reef.app", client=client)


def test_request_device_code_missing_field_raises():
    def handler(_):
        return httpx.Response(200, json={"device_code": "d"})  # no user_code

    with _client_from_handler(handler) as client, pytest.raises(AuthError):
        request_device_code("https://reef.app", client=client)


# ---------- poll_for_token ----------


def test_poll_immediate_success():
    """Token endpoint returns access_token on the first poll."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/devices/token"
        body = dict(httpx.QueryParams(request.content.decode()))
        assert body["grant_type"] == DEVICE_CODE_GRANT_TYPE
        assert body["device_code"] == "dev-secret"
        return httpx.Response(
            200,
            json={
                "access_token": "rfr_live",
                "refresh_token": "rfr_refresh",
                "token_type": "Bearer",
                "expires_in": 3600,
                "user": {"email": "alice@x.test", "id": "u"},
            },
        )

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client:
        result = poll_for_token(
            "https://reef.app",
            "dev-secret",
            interval=1.0,
            expires_in=60,
            client=client,
            sleep=sleep,
            now=now,
        )
    assert result.access_token == "rfr_live"
    assert result.refresh_token == "rfr_refresh"
    assert result.user == {"email": "alice@x.test", "id": "u"}


def test_poll_keeps_going_on_authorization_pending():
    """authorization_pending → loop until we get a real answer."""
    responses = iter(
        [
            httpx.Response(400, json={"error": "authorization_pending"}),
            httpx.Response(400, json={"error": "authorization_pending"}),
            httpx.Response(200, json={"access_token": "rfr_yes"}),
        ]
    )

    def handler(_):
        return next(responses)

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client:
        result = poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=120,
            client=client,
            sleep=sleep,
            now=now,
        )
    assert result.access_token == "rfr_yes"


def test_poll_slow_down_increases_interval():
    """slow_down increases the interval by 5s before the next poll."""
    sleep_calls: list[float] = []
    responses = iter(
        [
            httpx.Response(400, json={"error": "slow_down"}),
            httpx.Response(200, json={"access_token": "ok"}),
        ]
    )

    def handler(_):
        return next(responses)

    t = [0.0]

    def now():
        return t[0]

    def sleep(s):
        sleep_calls.append(s)
        t[0] += s

    with _client_from_handler(handler) as client:
        poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=600,
            client=client,
            sleep=sleep,
            now=now,
        )
    # First sleep is at the original interval; the second is +5s.
    assert sleep_calls[0] == 1.0
    assert sleep_calls[1] == pytest.approx(6.0)


def test_poll_access_denied_raises():
    def handler(_):
        return httpx.Response(400, json={"error": "access_denied"})

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client, pytest.raises(AccessDeniedError):
        poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=60,
            client=client,
            sleep=sleep,
            now=now,
        )


def test_poll_expired_token_raises():
    def handler(_):
        return httpx.Response(400, json={"error": "expired_token"})

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client, pytest.raises(AuthorizationExpiredError):
        poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=60,
            client=client,
            sleep=sleep,
            now=now,
        )


def test_poll_unknown_error_raises_auth_error():
    def handler(_):
        return httpx.Response(400, json={"error": "bogus_thing"})

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client, pytest.raises(AuthError):
        poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=60,
            client=client,
            sleep=sleep,
            now=now,
        )


def test_poll_deadline_expires_raises():
    """If the device_code expires_in is hit, raise AuthorizationExpiredError."""

    def handler(_):
        return httpx.Response(400, json={"error": "authorization_pending"})

    t = [0.0]

    def now():
        return t[0]

    def sleep(s):
        t[0] += s

    with _client_from_handler(handler) as client, pytest.raises(AuthorizationExpiredError):
        poll_for_token(
            "https://reef.app",
            "d",
            interval=10.0,
            expires_in=15,  # one ~10s sleep, second iter hits deadline
            client=client,
            sleep=sleep,
            now=now,
        )


def test_poll_network_error_keeps_polling():
    """Transient HTTPError → don't abort, just loop again."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("transient")
        return httpx.Response(200, json={"access_token": "ok"})

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client:
        result = poll_for_token(
            "https://reef.app",
            "d",
            interval=1.0,
            expires_in=60,
            client=client,
            sleep=sleep,
            now=now,
        )
    assert result.access_token == "ok"
    assert calls["n"] == 2


# ---------- device_login (end to end) ----------


def test_device_login_end_to_end_invokes_callback():
    """Make sure the on_user_code callback fires between steps 1 and 3."""
    state = {"step": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        state["step"] += 1
        if request.url.path == "/api/v1/devices/code":
            return httpx.Response(
                200,
                json={
                    "device_code": "d",
                    "user_code": "WXYZ",
                    "verification_uri": "https://reef.app/device",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        if request.url.path == "/api/v1/devices/token":
            return httpx.Response(200, json={"access_token": "ok"})
        raise AssertionError(f"unexpected path {request.url.path}")

    seen_code = {}

    def callback(code):
        seen_code["user_code"] = code.user_code

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client:
        code_resp, poll = device_login(
            "https://reef.app",
            on_user_code=callback,
            client=client,
            sleep=sleep,
            now=now,
        )

    assert code_resp.user_code == "WXYZ"
    assert seen_code["user_code"] == "WXYZ"
    assert poll.access_token == "ok"


def test_device_login_no_callback_still_works():
    """Tests that lack of callback doesn't crash the flow."""

    def handler(request):
        if request.url.path == "/api/v1/devices/code":
            return httpx.Response(
                200,
                json={
                    "device_code": "d",
                    "user_code": "U",
                    "verification_uri": "https://reef.app/device",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        return httpx.Response(200, json={"access_token": "ok"})

    now, sleep = _fake_clock()
    with _client_from_handler(handler) as client:
        _, poll = device_login(
            "https://reef.app",
            client=client,
            sleep=sleep,
            now=now,
        )
    assert poll.access_token == "ok"
