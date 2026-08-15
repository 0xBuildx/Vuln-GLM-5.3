from dataclasses import dataclass, asdict


@dataclass
class Order:
    id: str
    user_id: str
    tenant_id: str
    total_cents: int
    status: str
    items: list
    invoice_file: str

    def as_dict(self) -> dict:
        return asdict(self)


ORDERS = {
    "ord_100": Order(
        "ord_100",
        "u_10",
        "t_north",
        4200,
        "paid",
        [{"sku": "mug", "qty": 2, "unit_price": 2100}],
        "north/ada-ord-100.pdf",
    ),
    "ord_200": Order(
        "ord_200",
        "u_11",
        "t_south",
        9900,
        "paid",
        [{"sku": "lamp", "qty": 1, "unit_price": 9900}],
        "south/ben-ord-200.pdf",
    ),
    "ord_201": Order(
        "ord_201",
        "u_11",
        "t_south",
        150000,
        "paid",
        [{"sku": "desk", "qty": 1, "unit_price": 150000}],
        "south/ben-ord-201.pdf",
    ),
}
