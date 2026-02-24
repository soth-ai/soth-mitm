# `soth-proxy-adapter` Contract

This document defines the integration contract expected for the consumer-side adapter crate (`soth-proxy-adapter`) implemented in the `soth` repository.

## Goals

1. Keep `soth-mitm` proxy-core generic and policy/event deterministic.
2. Keep product-specific behavior (bundles, vendor routing, product semantics) outside proxy-core.
3. Provide a stable adapter contract for `intercept|tunnel|block` decision handlers and event consumption.

## Adapter Responsibilities

1. Translate `soth` policy/rules into proxy handler decisions.
2. Subscribe to deterministic event stream (`v1`) and map to `soth` internal schemas.
3. Preserve event ordering and sequence fields (`sequence_id`, `flow_sequence_id`).
4. Implement downstream persistence/forwarding without mutating core proxy semantics.

## Core Constraints

1. Adapter must not embed product bundles/rule packs inside `soth-mitm`.
2. Adapter must treat `tunnel` as metadata-only passthrough mode.
3. Adapter must preserve TLS source-confidence semantics:
   - authoritative sources can drive learning
   - inferred sources are audit-only

## Validation Contract

1. Conformance replay fixtures from `mitm-core` must remain unchanged.
2. Differential validation outputs from `scripts/p4_differential_validation.sh` must be consumed as-is.
3. Migration and cutover must use `docs/migration/soth-cutover.md` gate criteria.

## Ownership

- Proxy-core contract owner: `soth-mitm`.
- Consumer adapter implementation owner: `soth` repo (`soth-proxy-adapter`).
