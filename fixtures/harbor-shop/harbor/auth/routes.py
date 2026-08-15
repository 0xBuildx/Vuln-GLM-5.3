from .jwt_util import encode_token
from ..users.models import USERS


def login(email: str, password: str) -> dict:
    for user in USERS.values():
        if user.email == email and user.password == password:
            token = encode_token({"sub": user.id, "role": user.role})
            return {"token": token, "user": user.as_public()}
    raise PermissionError("invalid credentials")
