// @rea-protect
export function calculatePrice(base, rate, quantity) {
  return (base * rate + base) * quantity;
}

export default calculatePrice;
