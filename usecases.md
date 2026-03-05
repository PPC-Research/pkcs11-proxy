# Use Cases: mTLS + Per-Client Identity Authorization

This document describes practical scenarios for the proxy’s mTLS-based,
per‑client authorization and how they map to tests.

## 1) Centralized signing service (allow sign only)

**Scenario:** A CI runner or service needs to sign artifacts but must not be able
to create, destroy, or export keys.

**Policy intent:**
- Allow only `C_SignInit` / `C_Sign` and the minimum enumeration calls.
- Restrict to a specific token and key label.

**Test coverage:**
- `tests/per_client_identity.py::test_mtls_authz_allows_sign`
- `tests/per_client_identity.py::test_mtls_authz_denies_sign`

## 2) Read‑only inventory (enumeration only)

**Scenario:** A monitoring job should list tokens and objects but never
generate keys or sign.

**Policy intent:**
- Allow enumeration functions only.
- Deny `C_GenerateKeyPair`, `C_Sign*`, etc.

**Test coverage:**
- `tests/per_client_identity.py::test_mtls_authz_allows_enumeration_but_denies_keygen`

## 3) Default‑deny for unknown clients

**Scenario:** Only pre‑registered clients are allowed; all others are denied
even if they have a valid certificate from the CA.

**Policy intent:**
- `default: "deny"`
- No matching client entry for the caller.

**Test coverage:**
- `tests/per_client_identity.py::test_authz_default_deny_no_match`

## 4) Audit‑only rollout

**Scenario:** You want to see what would be denied without breaking existing
clients.

**Policy intent:**
- `PKCS11_PROXY_AUTHZ_MODE=audit`
- Log denials but allow operations.

**Test coverage:**
- `tests/per_client_identity.py::test_authz_audit_mode_logs_only`

## 5) Enforce requires verified peer cert

**Scenario:** Fail closed if clients don’t present a verified certificate.

**Policy intent:**
- `PKCS11_PROXY_AUTHZ_MODE=enforce`
- `PKCS11_PROXY_TLS_VERIFY_PEER=true` required

**Test coverage:**
- `tests/per_client_identity.py::test_authz_requires_peer_cert_when_enforced`

## 6) Key‑level scoping by label (best effort)

**Scenario:** A client can sign only with keys that match a label pattern.

**Policy intent:**
- `objects: ["SigningKey-*"]`
- Allow `C_Sign*`, deny sign for non‑matching labels.

**Test coverage:**
- `tests/per_client_identity.py::test_authz_object_label_scoping_denies_other_key`

## Notes

- Object scoping is **best effort**: if the label cannot be resolved from the
  request (or by an internal attribute lookup), the policy cannot enforce it.
- Function‑level checks are always enforced.
