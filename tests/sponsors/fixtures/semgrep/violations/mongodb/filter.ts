// Must fire: rg-mongo-dynamic-query (x2)
export function filterFor(field: string, value: string) {
  return { [field]: value, $where: "this.state == 'executed'" };
}
