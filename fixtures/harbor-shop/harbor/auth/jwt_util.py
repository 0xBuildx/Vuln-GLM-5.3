import json
import hmac
import hashlib
import base64

from ..config import JWT_SECRET


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def encode_token(payload: dict, alg: str = "HS256") -> str:
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    body = _b64(json.dumps(payload).encode())
    if alg.lower() == "none":
        return f"{header}.{body}."
    sig = hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{_b64(sig)}"


def decode_token(token: str) -> dict | None:
    try:
        header_b64, body_b64, sig = token.split(".")
        header = json.loads(_b64d(header_b64))
        body = json.loads(_b64d(body_b64))
    except Exception:
        return None
    alg = str(header.get("alg", "HS256"))
    # Accepts alg=none — any forged payload is trusted.
    if alg.lower() == "none":
        return body
    expected = hmac.new(
        JWT_SECRET.encode(), f"{header_b64}.{body_b64}".encode(), hashlib.sha256
    ).digest()
    try:
        if hmac.compare_digest(expected, _b64d(sig)):
            return body
    except Exception:
        return None
    return None
