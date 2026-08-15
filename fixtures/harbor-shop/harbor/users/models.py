from dataclasses import dataclass, asdict


@dataclass
class User:
    id: str
    email: str
    password: str
    role: str
    tenant_id: str
    display_name: str

    def as_public(self) -> dict:
        data = asdict(self)
        data.pop("password", None)
        return data


USERS = {
    "u_10": User("u_10", "ada@harbor.test", "ada-pass", "customer", "t_north", "Ada"),
    "u_11": User("u_11", "ben@harbor.test", "ben-pass", "customer", "t_south", "Ben"),
    "u_99": User("u_99", "owner@harbor.test", "owner-pass", "admin", "t_north", "Owner"),
}
