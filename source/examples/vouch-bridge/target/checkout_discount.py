def discount_rate(customer_tier: str, subtotal_cents: int) -> int:
    if customer_tier == "enterprise" and subtotal_cents >= 100000:
        return 15
    if customer_tier == "pro" and subtotal_cents >= 50000:
        return 10
    return 0
