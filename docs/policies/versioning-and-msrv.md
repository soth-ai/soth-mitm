# Versioning and MSRV Policy

## Rust Toolchain / MSRV

- Workspace `rust-version` is the MSRV contract (`Cargo.toml`).
- `rust-toolchain.toml` pins the default developer/CI toolchain.
- Current pinned toolchain: `1.88.0`.
- Current MSRV contract: `1.88`.

MSRV change policy:

1. MSRV bumps are allowed only in minor releases.
2. Patch releases must keep MSRV unchanged.
3. Any MSRV bump must be called out in release notes and changelog.

## SemVer Compatibility

Versioning policy for `soth-mitm` crates follows semantic versioning with these additional rules:

1. Patch releases:
   - no breaking public API changes
   - no event schema (`v1`) breaking changes
2. Minor releases:
   - additive API changes only
   - additive event attributes/events are allowed if they do not break existing consumers
   - MSRV bump allowed (per policy above)
3. Major releases:
   - required for any breaking API or event-schema contract changes

## Event Schema Contract (`v1`)

`mitm-observe` event schema is versioned. For `v1`:

1. Existing required fields must not be removed or renamed in patch/minor releases.
2. New optional attributes may be added in minor releases.
3. Ordering semantics (`sequence_id`, per-flow ordering behavior) are treated as compatibility-critical.

