export function discountRate(
  customerTier: string,
  subtotalCents: number
): number {
  if (customerTier === 'enterprise' && subtotalCents >= 100000) {
    return 15;
  }
  if (customerTier === 'pro' && subtotalCents >= 50000) {
    return 10;
  }
  return 0;
}
