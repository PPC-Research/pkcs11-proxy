# Test Coverage Matrix

This document maps real‑world scenarios and requirements to concrete tests.

## Coverage Matrix

| Scenario / Requirement | What is validated | Test(s) |
|---|---|---|
| Allow sign for authorized client | Allowed client can sign using existing key | `tests/per_client_identity.py::test_mtls_authz_allows_sign` |
| Deny sign for unauthorized client | Unauthorized client is denied sign | `tests/per_client_identity.py::test_mtls_authz_denies_sign` |
| Enumeration allowed, keygen denied | Read‑only client can enumerate but cannot generate keys | `tests/per_client_identity.py::test_mtls_authz_allows_enumeration_but_denies_keygen` |
| Default deny when no match | No client match ⇒ deny | `tests/per_client_identity.py::test_authz_default_deny_no_match` |
| Audit mode logs only | Operation succeeds; audit log produced | `tests/per_client_identity.py::test_authz_audit_mode_logs_only` |
| Enforce requires verified peer cert | Enforce mode denies without verified peer | `tests/per_client_identity.py::test_authz_requires_peer_cert_when_enforced` |
| Object label scoping | Access to non‑matching key labels is denied | `tests/per_client_identity.py::test_authz_object_label_scoping_denies_other_key` |
| Two clients, different perms | Positive + negative paths for two certs | `tests/per_client_identity.py::test_authz_two_clients_different_permissions` |
| Untrusted CA | Client cert signed by other CA denied | `tests/per_client_identity.py::test_authz_denies_untrusted_ca_and_self_signed` |
| Self‑signed client cert | Self‑signed cert denied | `tests/per_client_identity.py::test_authz_denies_untrusted_ca_and_self_signed` |
| SAN URI mismatch / missing SAN | `san_uri` matching fails without SAN | `tests/per_client_identity.py::test_authz_san_uri_match_requires_san` |

## Notes

- All listed tests are mTLS‑dependent and require `PKCS11_TEST_MTLS=1`.
- Some tests need `pkcs11-tool` and SoftHSM fixtures (`tests/setup-softhsm2.sh`).
