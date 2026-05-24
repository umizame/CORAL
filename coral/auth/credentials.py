"""Credentials file I/O.

Stored as JSON under `$XDG_CONFIG_HOME/coral/credentials.json` (defaults
to `~/.config/coral/credentials.json` on Linux/macOS). The location can
be overridden for tests / multi-account setups via `CORAL_AUTH_FILE`.

Schema (versioned via the top-level `version` field):

    {
      "version": 1,
      "active_provider": "https://reef.app",
      "providers": {
        "https://reef.app": {
          "access_token": "rfr_...",
          "refresh_token": "...",     // optional
          "token_type": "Bearer",
          "expires_at": "2026-05-25T10:00:00Z",   // optional, ISO 8601 UTC
          "user": {
            "email": "alice@example.com",
            "id": "uuid",
            "name": "Alice",
            "avatar_url": "https://..."
          }
        }
      }
    }

Writes are atomic (write to a sibling tempfile, fsync, rename) so a
crash mid-write can't corrupt the file. Mode is 0600 — the file holds
bearer tokens.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

CREDENTIALS_VERSION = 1


@dataclass
class UserInfo:
    """Identity returned by the provider's `/users/me` endpoint."""

    email: str | None = None
    id: str | None = None
    name: str | None = None
    avatar_url: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> UserInfo:
        return cls(
            email=d.get("email"),
            id=d.get("id"),
            name=d.get("name") or d.get("full_name"),
            avatar_url=d.get("avatar_url"),
        )


@dataclass
class ProviderCredentials:
    """Tokens + identity for a single provider URL."""

    access_token: str
    refresh_token: str | None = None
    token_type: str = "Bearer"
    expires_at: str | None = None
    user: UserInfo = field(default_factory=UserInfo)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProviderCredentials:
        return cls(
            access_token=d["access_token"],
            refresh_token=d.get("refresh_token"),
            token_type=d.get("token_type", "Bearer"),
            expires_at=d.get("expires_at"),
            user=UserInfo.from_dict(d.get("user") or {}),
        )

    def display_name(self) -> str:
        """Best human label for `coral whoami`-style output."""
        return self.user.email or self.user.name or self.user.id or "signed in"


@dataclass
class Credentials:
    """The whole credentials file content."""

    providers: dict[str, ProviderCredentials] = field(default_factory=dict)
    active_provider: str | None = None
    version: int = CREDENTIALS_VERSION

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Credentials:
        providers_raw = d.get("providers") or {}
        providers = {
            url: ProviderCredentials.from_dict(p) for url, p in providers_raw.items()
        }
        return cls(
            providers=providers,
            active_provider=d.get("active_provider"),
            version=int(d.get("version", CREDENTIALS_VERSION)),
        )

    def get_active(self) -> ProviderCredentials | None:
        if self.active_provider is None:
            return None
        return self.providers.get(self.active_provider)


def credentials_path() -> Path:
    """Resolve the credentials file path, honoring env overrides.

    Resolution order:
      1. `$CORAL_AUTH_FILE` (absolute path)
      2. `$XDG_CONFIG_HOME/coral/credentials.json`
      3. `~/.config/coral/credentials.json`
    """
    override = os.environ.get("CORAL_AUTH_FILE")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".config"
    return base / "coral" / "credentials.json"


def load_credentials(path: Path | None = None) -> Credentials:
    """Read the credentials file; return an empty `Credentials` if missing."""
    p = path or credentials_path()
    if not p.exists():
        return Credentials()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # Corrupt or unreadable file — surface as "no credentials" rather
        # than crashing the CLI. The user can `coral login` to overwrite.
        return Credentials()
    if not isinstance(data, dict):
        return Credentials()
    return Credentials.from_dict(data)


def save_credentials(creds: Credentials, path: Path | None = None) -> None:
    """Atomic write — tempfile + fsync + rename. Mode 0600."""
    p = path or credentials_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    payload = {
        "version": creds.version,
        "active_provider": creds.active_provider,
        "providers": {
            url: _provider_to_dict(pc) for url, pc in creds.providers.items()
        },
    }
    body = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    # NamedTemporaryFile in the same dir so the final rename is atomic
    # (cross-device renames aren't atomic on POSIX).
    fd, tmp_name = tempfile.mkstemp(
        prefix=".credentials.", suffix=".tmp", dir=str(p.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, p)
    except Exception:
        # Best-effort cleanup; ignore unlink errors (the OS will reap eventually).
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def delete_credentials(provider_url: str, path: Path | None = None) -> bool:
    """Remove tokens for one provider. Returns True if anything was removed.

    If the deleted provider was the active one, falls back to picking any
    remaining provider as the new active. With no providers left, the file
    itself is deleted to avoid leaving a stale empty struct on disk.
    """
    p = path or credentials_path()
    creds = load_credentials(p)
    if provider_url not in creds.providers:
        return False
    del creds.providers[provider_url]
    if creds.active_provider == provider_url:
        creds.active_provider = next(iter(creds.providers), None)
    if not creds.providers:
        # Empty — delete the file (and parent dir if empty).
        try:
            p.unlink()
        except OSError:
            pass
        return True
    save_credentials(creds, p)
    return True


def _provider_to_dict(pc: ProviderCredentials) -> dict[str, Any]:
    """Skip None/empty fields so the on-disk file stays small + readable."""
    d: dict[str, Any] = {
        "access_token": pc.access_token,
        "token_type": pc.token_type,
    }
    if pc.refresh_token:
        d["refresh_token"] = pc.refresh_token
    if pc.expires_at:
        d["expires_at"] = pc.expires_at
    user = asdict(pc.user)
    user = {k: v for k, v in user.items() if v}
    if user:
        d["user"] = user
    return d
