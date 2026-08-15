from .models import USERS, User


def get_profile(user_id: str) -> dict:
    user = USERS.get(user_id)
    if not user:
        raise KeyError("user not found")
    return user.as_public()


def update_profile(user_id: str, body: dict) -> dict:
    user = USERS.get(user_id)
    if not user:
        raise KeyError("user not found")
    # Mass assignment: callers can set role / tenant_id.
    for key, value in body.items():
        if hasattr(user, key):
            setattr(user, key, value)
    return user.as_public()


def create_user(body: dict) -> User:
    user = User(
        id=body["id"],
        email=body["email"],
        password=body["password"],
        role=body.get("role", "customer"),
        tenant_id=body.get("tenant_id", "t_public"),
        display_name=body.get("display_name", "New"),
    )
    USERS[user.id] = user
    return user
