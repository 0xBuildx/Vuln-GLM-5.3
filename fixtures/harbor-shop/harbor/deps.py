from .auth.jwt_util import decode_token
from .users.models import User, USERS


def get_current_user(authorization: str | None) -> User | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    payload = decode_token(authorization.split(" ", 1)[1])
    if not payload:
        return None
    return USERS.get(payload.get("sub"))


def require_user(authorization: str | None) -> User:
    user = get_current_user(authorization)
    if user is None:
        raise PermissionError("login required")
    return user


def require_admin(authorization: str | None) -> User:
    user = require_user(authorization)
    if user.role != "admin":
        raise PermissionError("admin only")
    return user
