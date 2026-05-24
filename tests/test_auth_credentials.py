"""Round-trip + atomic-write tests for `coral.auth.credentials`."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from coral.auth.credentials import (
    Credentials,
    ProviderCredentials,
    UserInfo,
    credentials_path,
    delete_credentials,
    load_credentials,
    save_credentials,
)


@pytest.fixture
def isolated_creds_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point CORAL_AUTH_FILE at a tmp file so the user's real creds are untouched."""
    p = tmp_path / "credentials.json"
    monkeypatch.setenv("CORAL_AUTH_FILE", str(p))
    return p


def _sample_creds(provider: str = "https://reef.example.com") -> Credentials:
    return Credentials(
        active_provider=provider,
        providers={
            provider: ProviderCredentials(
                access_token="rfr_test_token",
                refresh_token="rfr_refresh",
                token_type="Bearer",
                expires_at="2026-12-31T23:59:59Z",
                user=UserInfo(
                    email="alice@example.com",
                    id="user-uuid",
                    name="Alice Example",
                    avatar_url="https://example.com/a.png",
                ),
            )
        },
    )


def test_credentials_path_honors_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    target = tmp_path / "custom" / "creds.json"
    monkeypatch.setenv("CORAL_AUTH_FILE", str(target))
    assert credentials_path() == target


def test_credentials_path_falls_back_to_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("CORAL_AUTH_FILE", raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert credentials_path() == tmp_path / "coral" / "credentials.json"


def test_credentials_path_falls_back_to_home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("CORAL_AUTH_FILE", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert credentials_path() == tmp_path / ".config" / "coral" / "credentials.json"


def test_load_missing_returns_empty(isolated_creds_path: Path):
    creds = load_credentials()
    assert creds.providers == {}
    assert creds.active_provider is None
    assert creds.get_active() is None


def test_save_then_load_roundtrip(isolated_creds_path: Path):
    save_credentials(_sample_creds())
    creds = load_credentials()
    assert creds.active_provider == "https://reef.example.com"
    pc = creds.get_active()
    assert pc is not None
    assert pc.access_token == "rfr_test_token"
    assert pc.refresh_token == "rfr_refresh"
    assert pc.user.email == "alice@example.com"
    assert pc.user.id == "user-uuid"
    assert pc.user.name == "Alice Example"


def test_save_uses_mode_0600(isolated_creds_path: Path):
    save_credentials(_sample_creds())
    mode = stat.S_IMODE(os.stat(isolated_creds_path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_save_creates_parent_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """The parent dir is created when missing."""
    target = tmp_path / "new_dir" / "credentials.json"
    monkeypatch.setenv("CORAL_AUTH_FILE", str(target))
    save_credentials(_sample_creds())
    assert target.exists()


def test_save_strips_empty_user_fields(isolated_creds_path: Path):
    """Optional user fields shouldn't pollute the JSON when blank."""
    creds = Credentials(
        active_provider="https://x.test",
        providers={
            "https://x.test": ProviderCredentials(
                access_token="t",
                user=UserInfo(email=None, id=None, name=None, avatar_url=None),
            )
        },
    )
    save_credentials(creds)
    data = json.loads(isolated_creds_path.read_text())
    assert "user" not in data["providers"]["https://x.test"]


def test_load_corrupt_file_returns_empty(isolated_creds_path: Path):
    isolated_creds_path.write_text("not json {{")
    creds = load_credentials()
    assert creds.providers == {}


def test_delete_removes_one_provider(isolated_creds_path: Path):
    creds = Credentials(
        active_provider="https://a.test",
        providers={
            "https://a.test": ProviderCredentials(access_token="t1"),
            "https://b.test": ProviderCredentials(access_token="t2"),
        },
    )
    save_credentials(creds)
    assert delete_credentials("https://a.test") is True
    after = load_credentials()
    assert "https://a.test" not in after.providers
    assert "https://b.test" in after.providers
    # Active falls back to the remaining provider.
    assert after.active_provider == "https://b.test"


def test_delete_last_provider_removes_file(isolated_creds_path: Path):
    save_credentials(_sample_creds())
    assert isolated_creds_path.exists()
    assert delete_credentials("https://reef.example.com") is True
    assert not isolated_creds_path.exists()


def test_delete_unknown_provider_is_noop(isolated_creds_path: Path):
    save_credentials(_sample_creds())
    assert delete_credentials("https://nope.test") is False
    # Original creds untouched.
    after = load_credentials()
    assert "https://reef.example.com" in after.providers


def test_provider_display_name_prefers_email():
    pc = ProviderCredentials(
        access_token="t",
        user=UserInfo(email="e@x.test", name="Name", id="i"),
    )
    assert pc.display_name() == "e@x.test"


def test_provider_display_name_falls_through_to_id():
    pc = ProviderCredentials(
        access_token="t",
        user=UserInfo(email=None, name=None, id="abc"),
    )
    assert pc.display_name() == "abc"


def test_provider_display_name_last_resort():
    pc = ProviderCredentials(access_token="t", user=UserInfo())
    assert pc.display_name() == "signed in"
