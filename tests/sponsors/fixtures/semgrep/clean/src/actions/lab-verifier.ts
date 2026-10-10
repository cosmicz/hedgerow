// Must not fire: the exact reviewed lab verifier path is exempt.
export const probe = () => Bun.spawn(["sh", "test/dnsq.sh", "update-check.cloudsyncapi.net", "10.77.0.53"]);
