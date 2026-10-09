// Must not fire: fixed keys, untrusted values only as values.
export function filterFor(digest: string) {
  return { _id: digest, state: "approved" };
}
