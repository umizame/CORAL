"""Account auth — link a local CORAL install to a hosted dashboard / hub.

CORAL itself stays provider-agnostic: any service that implements the
OAuth 2.0 Device Authorization Grant (RFC 8628) endpoints described in
`device.py` can be a provider. Reef, Coral Cloud, an internal company
dashboard — same protocol.

Public API:

    from coral.auth import (
        load_credentials, save_credentials, delete_credentials,
        device_login, AuthError, AccessDenied, AuthorizationExpired,
    )

The CLI surface (`coral login`, `coral logout`, `coral whoami`,
`coral providers`) is in `coral/cli/auth.py`; this package is the
reusable building block underneath.
"""

from __future__ import annotations

from coral.auth.credentials import (
    Credentials,
    ProviderCredentials,
    UserInfo,
    credentials_path,
    delete_credentials,
    load_credentials,
    save_credentials,
)
from coral.auth.device import (
    AccessDenied,
    AuthError,
    AuthorizationExpired,
    DeviceCodeResponse,
    device_login,
    fetch_user_info,
    normalize_provider_url,
)

__all__ = [
    "AccessDenied",
    "AuthError",
    "AuthorizationExpired",
    "Credentials",
    "DeviceCodeResponse",
    "ProviderCredentials",
    "UserInfo",
    "credentials_path",
    "delete_credentials",
    "device_login",
    "fetch_user_info",
    "load_credentials",
    "normalize_provider_url",
    "save_credentials",
]
