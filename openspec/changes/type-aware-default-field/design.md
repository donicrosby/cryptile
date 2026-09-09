# Design: type-aware-default-field

## Approach

Type detection is the wrong frame; shape detection is the right one. The
provider maps every cipher type into one flat field bag, and the bag's shape
encodes the type. So the default-field logic is a fixed chain over the bag:

```text
password → notes → private_key → number
```

Rationale per hop:

- `password` — today's default; Login items keep identical behavior.
- `notes` — Secure Note's value field; also the catch-all for items whose
  payload lives in notes (agent keys pasted into a note, recovery codes...).
- `private_key` — SSH Key items where the key material is the secret.
- `number` — Card items; the number is the secret you'd pipe somewhere.

First non-empty hit wins. Chain constant lives next to `Ref::DEFAULT_FIELD`
in core — one place, one order, both backends and the CLI read the same list.

## Explicit vs defaulted fragment

`Ref` gains `field_explicit: bool` (serde default false). Only defaulted refs
walk the chain in `ops::get`. This is the safety valve: `#password` asked
aloud keeps failing loudly when absent — silent field substitution under an
explicit selector would be a correctness bug (you asked for THAT field).

`Display` keeps emitting `scheme://locus#field` with the (possibly defaulted)
field — round-trip parse(`to_string()`) is unchanged. Hash/Eq derive over all
fields including `field_explicit`; no map keys are expected to collide
(same scheme+locus+field with differing explicitness does not occur in the
registry flow — refs are parsed once from user input where explicitness is
fixed by the string).

## Alternatives considered

- **Type table (VW type → default field) in the VW provider.** Couples the
  default to a provider, needs a trait change or provider-specific hook to
  surface, and does nothing for future backends. Rejected.
- **Failing with a "did you mean #notes?" hint.** Keeps failure but improves
  the message. Weaker than fixing the resolution; the chain subsumes it.
- **`Secret::default_field()` provider-computed at map time.** Requires
  threading a preference through `map_cipher` per item type — same type-table
  coupling, more surface. Rejected.

## Invariants

- No behavior change for explicit fragments — exact same lookup, exact same
  error text on absence.
- Empty-string fields are never selected by the chain (skipped, not
  returned).
- No plaintext in new code paths: `primary_value()` returns `&SecretString`,
  exposure stays at the stdout boundary.
