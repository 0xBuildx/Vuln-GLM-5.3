# Harbor Shop

Intentionally vulnerable demo store used by Vuln to show cross-file reasoning.

Not a real product. Do not deploy.

Planted issues:

- IDOR on order fetch (`orders/service.py` ignores the caller)
- Admin export with no role check
- Checkout trusts client-supplied `unit_price`
- Mass assignment of `role` on profile update
- JWT `alg=none` + hardcoded secret
- Path traversal on invoice download
- String-built SQL in search
