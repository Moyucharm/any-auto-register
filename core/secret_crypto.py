from __future__ import annotations

import base64
import hashlib
import os
import secrets
from functools import lru_cache
from pathlib import Path

from jwcrypto import jwe, jwk
from sqlalchemy.types import Text, TypeDecorator

_ENCRYPTION_PREFIX = "enc:v1:"
_DEFAULT_KEY_FILE = "data_encryption.key"


def _chmod_best_effort(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError:
        return


def _default_key_dir() -> Path:
    runtime_dir = str(os.getenv("APP_RUNTIME_DIR", "") or "").strip()
    if runtime_dir:
        return Path(runtime_dir).expanduser().resolve() / "secrets"
    return Path.home() / ".any-auto-register"


def _key_file_path() -> Path:
    raw_path = str(os.getenv("APP_DATA_ENCRYPTION_KEY_FILE", "") or "").strip()
    if raw_path:
        return Path(raw_path).expanduser().resolve()
    return _default_key_dir() / _DEFAULT_KEY_FILE


def _ensure_local_secret_file(path: Path, *, default_value: str = "") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    _chmod_best_effort(path.parent, 0o700)
    if path.exists():
        return path.read_text(encoding="utf-8").strip()

    secret_text = str(default_value or "").strip() or secrets.token_urlsafe(48)
    path.write_text(secret_text, encoding="utf-8")
    _chmod_best_effort(path, 0o600)
    return secret_text


def load_persistent_secret(
    *,
    env_name: str,
    file_name: str,
    legacy_value: str = "",
) -> str:
    env_secret = str(os.getenv(env_name, "") or "").strip()
    if env_secret:
        return env_secret
    return _ensure_local_secret_file(
        _default_key_dir() / file_name,
        default_value=legacy_value,
    )


def _master_secret_text() -> str:
    env_secret = str(os.getenv("APP_DATA_ENCRYPTION_KEY", "") or "").strip()
    if env_secret:
        return env_secret
    return _ensure_local_secret_file(_key_file_path())


@lru_cache(maxsize=1)
def _jwe_key() -> jwk.JWK:
    key_bytes = hashlib.sha256(_master_secret_text().encode("utf-8")).digest()
    key_material = base64.urlsafe_b64encode(key_bytes).rstrip(b"=").decode("ascii")
    return jwk.JWK(kty="oct", k=key_material)


def is_encrypted_text(value: str | None) -> bool:
    return str(value or "").startswith(_ENCRYPTION_PREFIX)


def encrypt_text(value: str | None) -> str | None:
    if value is None:
        return None

    text = str(value)
    if not text or is_encrypted_text(text):
        return text

    token = jwe.JWE(
        plaintext=text.encode("utf-8"),
        protected={"alg": "dir", "enc": "A256GCM"},
    )
    token.add_recipient(_jwe_key())
    return f"{_ENCRYPTION_PREFIX}{token.serialize(compact=True)}"


def decrypt_text(value: str | None) -> str | None:
    if value is None:
        return None

    text = str(value)
    if not text or not is_encrypted_text(text):
        return text

    compact = text[len(_ENCRYPTION_PREFIX):]
    token = jwe.JWE()
    try:
        token.deserialize(compact, key=_jwe_key())
    except Exception as exc:
        raise RuntimeError(
            "敏感数据解密失败，请确认 APP_DATA_ENCRYPTION_KEY 或本地密钥文件与现有数据匹配"
        ) from exc

    payload = token.payload
    if isinstance(payload, bytes):
        return payload.decode("utf-8")
    return str(payload or "")


class EncryptedText(TypeDecorator):
    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return encrypt_text(value)

    def process_result_value(self, value, dialect):
        return decrypt_text(value)
