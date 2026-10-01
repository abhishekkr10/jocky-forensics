import os
import pytest

from backend.app import integrity
from backend.app.auth import create_user


def test_short_demo_password_is_rejected():
    with pytest.raises(ValueError, match="12 characters"):
        create_user("short-password-user", "test123")


def test_signing_key_migrates_out_of_data_directory(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    legacy = data / "checkpoint.key"
    legacy.write_bytes(os.urandom(32))
    moved = tmp_path / "keys" / "checkpoint.key"
    monkeypatch.setattr(integrity, "DATA", data)
    monkeypatch.setenv("JOCKY_KEY_PATH", str(moved))

    integrity.signing_key()

    assert moved.exists()
    assert not legacy.exists()
    assert len(integrity.public_key()) == 64
