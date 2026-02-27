# TLS Taxonomy

This document defines the normalized TLS failure taxonomy used by `soth-mitm` eventing and hardening lanes.

## Normalized Reasons

| Code | Meaning |
| --- | --- |
| `unknown_ca` | trust chain does not anchor in trusted CA set |
| `cert_validation` | cert validity/name/chain validation failed |
| `handshake` | protocol/alert-level handshake failure |
| `timeout` | handshake or transport timeout |
| `eof_or_reset` | abrupt EOF/reset/connection-abort during TLS lifecycle |
| `other` | uncategorized provider/runtime error |

## Required TLS Metadata Fields

Every TLS failed event must include:

1. `tls_failure_reason`
2. `detail`
3. `tls_failure_source`
4. `tls_ops_provider`
5. `normalized_reason`
6. `raw_provider_error`
7. `provider_identity`
8. `source_confidence`
9. `upstream_ocsp_staple_present`
10. `upstream_ocsp_staple_status`
11. `revocation_policy_mode`
12. `revocation_decision`
13. `tls_fingerprint_mode`
14. `tls_fingerprint_class`

## Validation Commands

```bash
./scripts/tls_failure_fixtures.sh
cargo test -p mitm-sidecar --test mitmproxy_tls_adapter
cargo test -p mitm-sidecar --test tls_learning_guardrails
cargo test -p mitm-sidecar --test tls_revocation_matrix
cargo test -p mitm-sidecar --test tls_upstream_mtls_matrix
cargo test -p mitm-sidecar --test tls_fingerprint_parity
cargo test -p soth-mitm --lib fingerprint_capture
./scripts/p6_tls_revocation_matrix.sh
./scripts/p6_tls_mtls_matrix.sh
./scripts/p6_tls_fingerprint_parity.sh
./scripts/p6_tls_compat_pack.sh
```

## Classification Invariants

1. Classification must be deterministic for identical error text.
2. `unknown_ca` and `timeout` keyword buckets must remain stable.
3. Inferred providers must not update learning state.
