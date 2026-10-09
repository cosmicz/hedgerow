# Hedgerow demo guidance: reading a DNS deny and a model judgment

Public, demo-only guidance for the Hedgerow prototype. It contains no household
data, device names, addresses, logs or credentials. It explains how to interpret
what the demo shows; it does not authorize any action.

## What a DNS deny rule does and does not do

A DNS deny rule tells the resolver to refuse one exact domain for one client
group. Hedgerow adds such a rule only after explicit operator approval, records
it in its own journal, verifies the effect with an independent lookup, and can
undo it.

A DNS deny rule does not end connections that already exist. It does not clear
every device's DNS cache, so a device may keep using an answer it already has
until that answer expires. It does not stop a device that connects to an IP
address directly, uses a different resolver, or uses encrypted DNS that bypasses
the local resolver. It does not remove malware, and it does not quarantine a
device. The correct label for the action is "DNS deny rule", not "device
quarantined" or "attack stopped".

Verification measures one thing: after the rule, a lookup of the denied domain
from the probe client is blocked while a lookup of a benign domain still
resolves. That is evidence the rule is in effect on that resolver for that
client group, not evidence that the network is safe.

## Measured evidence versus model judgment

Measured evidence is what a collector observed: a DNS lookup, its time, the
client group, and whether it was answered or blocked. Each observation keeps its
source, its time and its mode (synthetic, replay, VM-live or physical-live).
Deterministic rules turn observations into findings, and a finding names the
observations it rests on.

A model judgment (for example a Jev or Clef classification of a domain as
benign, suspicious or unknown) is an opinion about measured evidence. It can be
wrong, it can abstain, and it is never a substitute for a missing or stale
observation. A model judgment cannot approve, execute or undo an action; only
deterministic policy and an explicit operator approval can.

When the two disagree, report both. "Unknown" means there is not enough
evidence; it must not be shown as healthy. Synthetic and replayed evidence must
be labelled as such and never presented as live.
