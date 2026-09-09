# Proposal: type-aware-default-field

## Why

Refs without a fragment default to `#password`. On a Login that's right; on a
Secure Note it's an error (`field 'password' not present`), on a Card it's a
low-value field when the user almost certainly wants the number, on an SSH Key
it's missing entirely. Users write `vw://RJ-45/Dolos Lemonade Key` in a config
and get a confusing failure on an item that plainly exists and decrypts.

## What Changes

- `Ref` records whether the fragment was explicit (`field_explicit`).
- `Secret::primary_value()` walks a fallback chain over the field bag:
  `password → notes → private_key → number`, first hit wins. Empty strings
  are skipped. Deterministic: BTreeMap iteration is not consulted — the chain
  order is fixed.
- `ops::get` uses `field()` when the fragment was explicit; `primary_value()`
  when it was defaulted. Explicit `#password` on a note keeps failing with
  today's exact error — no silent substitution of a different field than the
  one requested.
- README: default-field semantics updated (chain table).

## Impact

- `vw://coll/item` now resolves on every cipher type. Explicit refs are
  byte-for-byte unchanged semantics.
- Not a Provider-trait change; the chain is a fact about the field bag, not
  about Vaultwarden item types — future backends (op, vault) inherit it.
- The live LEMONADE ref in the Hermes config keeps `#notes` (explicit beats
  clever), but the bare ref now also works.

## Non-goals

- Provider-specific or user-configurable chains.
- Changing `Ref::DEFAULT_FIELD` (still `password`, still what Display emits).
