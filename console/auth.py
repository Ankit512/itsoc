#!/usr/bin/env python3
"""
auth.py — Authentication provider interface & local single-profile demo stub.

Philosophy & Architecture:
- Token / passkey auth design philosophy: While a passphrase is used for demo
  familiarity, the architecture is built around a pluggable BaseAuthProvider
  interface so a real OIDC, WebAuthn/Passkey, or OAuth token provider drops in
  with zero UI rewrites.
- Local demo stub: Stores a single profile in console/.soc/auth.json.
- Security: Passphrases are hashed with salt using hashlib.scrypt (or
  hashlib.pbkdf2_hmac if scrypt is unavailable). Plaintext is never stored
  and never returned over any API.
- Sessions: Issues cryptographically secure random session tokens (secrets.token_hex).
"""

import abc
import hashlib
import hmac
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOC_DIR = HERE / ".soc"
AUTH_FILE = "auth.json"
SESSION_TTL_HOURS = 24


class ProfileExistsError(ValueError):
    """The single local profile has already been bootstrapped."""


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_passphrase(passphrase: str, salt: bytes = None) -> tuple[str, str]:
    """Hash passphrase with salt using scrypt or pbkdf2. Returns (algo$hex_hash, hex_salt)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    pass_bytes = passphrase.encode("utf-8")
    try:
        derived = hashlib.scrypt(pass_bytes, salt=salt, n=16384, r=8, p=1, maxmem=0, dklen=32)
        algo = "scrypt"
    except (AttributeError, ValueError):
        derived = hashlib.pbkdf2_hmac("sha256", pass_bytes, salt, 100000, dklen=32)
        algo = "pbkdf2_sha256"
    return f"{algo}${derived.hex()}", salt.hex()


def _verify_passphrase(passphrase: str, stored_hash: str, salt_hex: str) -> bool:
    """Constant-time verification of passphrase against stored hash."""
    if not stored_hash or not salt_hex:
        return False
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    algo, _, hash_val = stored_hash.partition("$")
    pass_bytes = passphrase.encode("utf-8")
    if algo == "scrypt" and hasattr(hashlib, "scrypt"):
        try:
            derived = hashlib.scrypt(pass_bytes, salt=salt, n=16384, r=8, p=1, maxmem=0, dklen=32)
            return hmac.compare_digest(derived.hex(), hash_val)
        except Exception:
            return False
    else:
        derived = hashlib.pbkdf2_hmac("sha256", pass_bytes, salt, 100000, dklen=32)
        return hmac.compare_digest(derived.hex(), hash_val)


class BaseAuthProvider(abc.ABC):
    """Abstract interface for auth providers (Local demo, OIDC, Passkey)."""

    @abc.abstractmethod
    def get_status(self) -> dict:
        """Return provider status and whether a profile is initialized."""
        pass

    @abc.abstractmethod
    def signup(self, username: str, passphrase: str, role: str = "analyst") -> tuple[dict, str]:
        """Bootstrap the single profile. Returns (user_dict, token)."""
        pass

    @abc.abstractmethod
    def login(self, username: str, passphrase: str) -> tuple[dict, str]:
        """Authenticate with credentials. Returns (user_dict, token)."""
        pass

    @abc.abstractmethod
    def authenticate_token(self, token: str) -> dict | None:
        """Validate session token. Returns user_dict or None."""
        pass

    @abc.abstractmethod
    def logout(self, token: str) -> bool:
        """Invalidate session token."""
        pass


class LocalDemoAuth(BaseAuthProvider):
    """Local single-profile demo stub storing salt+hash in .soc/auth.json."""

    def __init__(self, soc_dir: Path = None):
        self.soc_dir = soc_dir or SOC_DIR
        self._sessions: dict[str, dict] = {}

    def _auth_path(self) -> Path:
        self.soc_dir.mkdir(parents=True, exist_ok=True)
        return self.soc_dir / AUTH_FILE

    def _load_profile(self) -> dict | None:
        path = self._auth_path()
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and "username" in data and "hash" in data:
                return data
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _save_profile(self, profile: dict):
        path = self._auth_path()
        payload = json.dumps(profile, indent=2)
        # Credential records must not be left truncated after a crash and are
        # private to the local user account.
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def get_status(self) -> dict:
        profile = self._load_profile()
        return {
            "hasProfile": profile is not None,
            "authType": "local_demo",
            "provider": "LocalDemoAuth",
            "principle": "token_passkey_ready",
            "disclaimer": "Local demo — a single profile on this machine. No enterprise SSO is faked.",
            "activeUsername": profile.get("username") if profile else None,
        }

    def signup(self, username: str, passphrase: str, role: str = "analyst") -> tuple[dict, str]:
        if self._load_profile() is not None:
            raise ProfileExistsError("Local demo profile already exists; sign in instead.")
        username = str(username or "").strip()
        if not username:
            raise ValueError("username cannot be empty")
        if len(passphrase or "") < 4:
            raise ValueError("passphrase must be at least 4 characters")
        # No RBAC exists in the local demo. Caller-selected roles would imply
        # privileges that are neither implemented nor safe to self-assign.
        role = "analyst"

        hashed, salt_hex = _hash_passphrase(passphrase)
        profile = {
            "username": username,
            "role": role,
            "hash": hashed,
            "salt": salt_hex,
            "createdAt": _now(),
            "updatedAt": _now(),
        }
        self._save_profile(profile)
        user = {"username": username, "role": role, "createdAt": profile["createdAt"]}
        token = self._create_session(user)
        return user, token

    def login(self, username: str, passphrase: str) -> tuple[dict, str]:
        username = str(username or "").strip()
        profile = self._load_profile()
        if not profile:
            raise PermissionError("No local profile created yet. Please create a profile first.")

        if profile.get("username") != username:
            raise PermissionError("Invalid username or passphrase")

        if not _verify_passphrase(passphrase, profile.get("hash", ""), profile.get("salt", "")):
            raise PermissionError("Invalid username or passphrase")

        user = {"username": profile["username"], "role": profile.get("role", "analyst"), "createdAt": profile.get("createdAt")}
        token = self._create_session(user)
        return user, token

    def _create_session(self, user: dict) -> str:
        token = secrets.token_hex(32)
        expires_at = datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)
        self._sessions[token] = {
            "user": user,
            "expiresAt": expires_at.isoformat()
        }
        return token

    def authenticate_token(self, token: str) -> dict | None:
        if not token or not isinstance(token, str):
            return None
        sess = self._sessions.get(token)
        if not sess:
            return None
        try:
            exp = datetime.fromisoformat(sess["expiresAt"])
            if datetime.now(timezone.utc) > exp:
                del self._sessions[token]
                return None
        except Exception:
            return None
        return sess.get("user")

    def logout(self, token: str) -> bool:
        if token in self._sessions:
            del self._sessions[token]
            return True
        return False


# Singleton provider instance
AUTH_PROVIDER = LocalDemoAuth()
