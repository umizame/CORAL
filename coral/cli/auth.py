"""CLI command handlers for account auth.

Commands wired into `coral/cli/__init__.py`:

    coral login <provider-url>       Link this machine to a hosted account.
    coral logout [provider-url]      Drop tokens for one provider (or active).
    coral whoami                     Show the active account.
    coral providers                  List all linked providers; mark the
                                     active one.

The actual flow lives in `coral.auth`; this file is the user-facing glue
(stdout messages, browser-open behavior, exit codes).
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
import webbrowser
from datetime import timezone

from coral.auth import (
    AccessDenied,
    AuthError,
    AuthorizationExpired,
    Credentials,
    DeviceCodeResponse,
    ProviderCredentials,
    UserInfo,
    credentials_path,
    delete_credentials,
    device_login,
    fetch_user_info,
    load_credentials,
    normalize_provider_url,
    save_credentials,
)


def _print_user_code(code: DeviceCodeResponse, *, open_browser: bool) -> None:
    """Show the user what to do next + optionally open the browser.

    The convention `gh auth login` set is: print the URL on one line and
    the code on its own line (easy to copy on terminals without word-wrap
    smartness), then a blank line before the polling status.
    """
    url = code.verification_url
    complete_url = code.verification_url_complete or url
    print()
    print(f"  Open: {url}")
    print(f"  Code: {code.user_code}")
    print()
    if open_browser:
        opened = False
        try:
            opened = webbrowser.open(complete_url, new=2)
        except Exception:
            opened = False
        if opened:
            print("  (opened in your browser)")
        else:
            print("  (couldn't open a browser — visit the URL manually)")
    print("\nWaiting for you to authorize this device…", flush=True)


def cmd_login(args: argparse.Namespace) -> None:
    """`coral login <provider-url>` — device-grant flow + save tokens."""
    try:
        provider_url = normalize_provider_url(args.provider)
    except AuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    print(f"Logging in to {provider_url}")

    try:
        code_resp, poll = device_login(
            provider_url,
            on_user_code=lambda c: _print_user_code(c, open_browser=not args.no_browser),
        )
    except AccessDenied:
        print("error: authorization denied by user", file=sys.stderr)
        sys.exit(1)
    except AuthorizationExpired:
        print(
            "error: the device code expired before you authorized it. "
            "Run `coral login` again.",
            file=sys.stderr,
        )
        sys.exit(1)
    except AuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    # Best-effort identity fetch — fall back to whatever the token endpoint
    # inlined under `user`. If both fail we just record the token; whoami
    # will display the bare provider URL.
    user_payload = poll.user
    if user_payload is None:
        user_payload = fetch_user_info(provider_url, poll.access_token)
    user_info = UserInfo.from_dict(user_payload or {})

    expires_at = None
    if poll.expires_in is not None:
        expires_at = (
            _dt.datetime.now(timezone.utc) + _dt.timedelta(seconds=poll.expires_in)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

    creds = load_credentials()
    creds.providers[provider_url] = ProviderCredentials(
        access_token=poll.access_token,
        refresh_token=poll.refresh_token,
        token_type=poll.token_type,
        expires_at=expires_at,
        user=user_info,
    )
    # Newly-added provider becomes active. The user can `coral providers`
    # to see all of them and pick another active one later (when we ship
    # the switch UX).
    creds.active_provider = provider_url
    save_credentials(creds)

    display = user_info.email or user_info.name or user_info.id
    if display:
        print(f"\n✓ Logged in to {provider_url} as {display}")
    else:
        print(f"\n✓ Logged in to {provider_url}")
    print(f"  Credentials saved to {credentials_path()}")


def cmd_logout(args: argparse.Namespace) -> None:
    """`coral logout [provider-url]` — drop tokens for one provider.

    With no URL, logs out of the active provider. With `--all`, removes
    every provider.
    """
    creds = load_credentials()

    if args.all:
        if not creds.providers:
            print("Not logged in to any provider.")
            return
        urls = list(creds.providers.keys())
        for url in urls:
            delete_credentials(url)
        print(f"Logged out of {len(urls)} provider(s).")
        return

    provider_arg = args.provider
    if provider_arg is None:
        if creds.active_provider is None:
            print("Not logged in to any provider.")
            return
        provider_arg = creds.active_provider

    try:
        provider_url = normalize_provider_url(provider_arg)
    except AuthError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(2)

    removed = delete_credentials(provider_url)
    if not removed:
        print(f"Not logged in to {provider_url}.")
        sys.exit(1)
    print(f"Logged out of {provider_url}.")


def cmd_whoami(args: argparse.Namespace) -> None:
    """`coral whoami` — show the active account (or one named via --provider)."""
    creds = load_credentials()
    if args.provider:
        try:
            provider_url = normalize_provider_url(args.provider)
        except AuthError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(2)
        pc = creds.providers.get(provider_url)
    else:
        provider_url = creds.active_provider
        pc = creds.get_active()

    if pc is None or provider_url is None:
        print("Not logged in. Run `coral login <provider-url>` to authenticate.")
        sys.exit(1)

    print(f"{pc.display_name()}")
    print(f"  Provider:  {provider_url}")
    if pc.user.id:
        print(f"  User ID:   {pc.user.id}")
    if pc.user.name and pc.user.name != pc.user.email:
        print(f"  Name:      {pc.user.name}")
    if pc.expires_at:
        print(f"  Expires:   {pc.expires_at}")
    print(f"  File:      {credentials_path()}")


def cmd_providers(args: argparse.Namespace) -> None:  # noqa: ARG001 — argparse passes args
    """`coral providers` — list every linked provider with its identity."""
    creds = load_credentials()
    if not creds.providers:
        print("No providers configured. Run `coral login <provider-url>`.")
        return

    rows = []
    for url, pc in sorted(creds.providers.items()):
        marker = "*" if url == creds.active_provider else " "
        rows.append((marker, url, pc.display_name()))

    width = max(len(r[1]) for r in rows)
    for marker, url, who in rows:
        print(f"{marker} {url.ljust(width)}  {who}")
    print("\n* = active provider")


# Re-export for argparse `default=` if the dispatcher ever wants to no-op.
def _noop(_: argparse.Namespace) -> None:  # pragma: no cover
    pass
