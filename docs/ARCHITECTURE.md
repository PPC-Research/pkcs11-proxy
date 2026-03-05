# Architecture: mTLS + Per-Client Identity Authorization

This document explains how the proxy enforces per-client authorization using
mTLS client certificates, how requests flow internally, and how to deploy it
with a remote HSM back-end.

## 1) Goals and guarantees

- **Mutual TLS identity**: every client presents an X.509 certificate; the
  daemon verifies it against a CA and extracts a stable client identity.
- **Server-side authorization**: policy is enforced by the daemon before any
  PKCS#11 call reaches the underlying module. Clients cannot bypass it.
- **Scoped access**: policy can restrict by PKCS#11 function, token label, and
  object label (best effort).
- **Audit and rollout**: audit mode allows observing would‑be denies without
  breaking clients.

## 2) Components

```
Client app ──> libpkcs11-proxy.so ──TLS/mTLS──> pkcs11-daemon ──> PKCS#11 module
                                                       (SoftHSM, netHSM, etc.)
```

Key files:
- `gck-rpc-tls.c`: TLS handshake, peer cert extraction.
- `gck-rpc-dispatch.c`: request dispatch path (enforcement happens here).
- `gck-rpc-authz.c`: policy load, identity extraction, authorization checks.
- `authz-policy-parser.c`: policy JSON parser used by the daemon.

## 3) Identity model

When `PKCS11_PROXY_TLS_VERIFY_PEER=true` and TLS is enabled:

1. The daemon obtains the peer certificate from the TLS session.
2. It computes identity attributes:
   - **Primary**: SHA‑256 fingerprint of the DER cert (hex, lowercase).
   - **Subject**: subject DN string (best effort, for logs).
   - **SANs**: DNS/URI/IP entries (best effort).
3. This identity is stored in the per‑connection authz context and is used for
   all subsequent RPCs on that connection.

If enforcement is enabled but no verified peer certificate exists, the daemon
denies requests by default (least privilege).

## 4) Policy model

Policy JSON contains:

- `version` (int)
- `default`: `"allow"` or `"deny"`
- `clients`: list of matchers with `allow` rules

Matchers:
- `cert_fingerprint_sha256` (exact match, preferred)
- `subject_cn` (glob match)
- `san_uri` (glob match)

Allow rules can include:
- `pkcs11_functions` (function names, e.g. `C_SignInit`)
- `tokens` (token label globs)
- `objects` (object label globs)

If multiple client matchers apply, allow rules are **unioned**.

## 5) Request flow and enforcement

For each incoming RPC:

1. **Basic check**: before dispatching to the module, the daemon checks if
   the function is allowed for this client.
2. **Scoped check** (best effort): for requests that include a token label,
   object label, or attributes with `CKA_LABEL`, the daemon matches against
   allowed tokens/objects.
3. If denied, the daemon returns:
   - `CKR_FUNCTION_NOT_PERMITTED` if available
   - otherwise `CKR_GENERAL_ERROR`
4. Denials are logged with fingerprint, subject, function, token/object when
   available.

The underlying PKCS#11 module is **not called** on denied requests.

## 6) Why enumeration can hang when a function is denied

Tools like `pkcs11-tool` repeatedly call certain functions during
enumeration/login. If a required function is denied (e.g. `C_GetSessionInfo`,
`C_GetMechanismList`, `C_GenerateRandom`), the tool may loop indefinitely.

Mitigation: include the relevant enumeration calls in the client’s allow list.
See **Operational guidance** below for a safe baseline.

## 7) Remote HSM deployment (netHSM / cloud)

### Typical topology

```
Client VMs
  └─ libpkcs11-proxy.so
       └─ TLS/mTLS to pkcs11-daemon (proxy host)
            └─ PKCS#11 module that talks to remote HSM (netHSM)
```

The daemon host acts as a **policy enforcement point** in front of the remote
HSM. Benefits:

- Centralized policy: add/remove client access by updating a single policy file.
- mTLS-based identity: no per-client secrets embedded in applications.
- Isolation: clients never connect directly to the remote HSM.

### Recommended setup

- Place `pkcs11-daemon` on a host with direct access to HSM.
- Configure TLS with a dedicated CA for client certs.
- For each client VM:
  - issue a client cert (unique per VM or per workload).
  - add a policy entry for that cert fingerprint.
- Keep `PKCS11_PROXY_TLS_VERIFY_PEER=true` and `PKCS11_PROXY_AUTHZ_MODE=enforce`.

### Rotation and hygiene

- Rotate client certs regularly; update fingerprints in the policy.
- Use short‑lived certs for ephemeral workloads.
- Prefer audit mode when rolling out new policies to avoid surprise denies.

## 8) Operational guidance (baseline allow list)

The following functions are typically needed for read‑only enumeration and
basic login:

```
C_Initialize, C_Finalize, C_GetInfo, C_GetSlotList, C_GetSlotInfo,
C_GetTokenInfo, C_GetMechanismList, C_OpenSession, C_CloseSession,
C_GetSessionInfo, C_Login, C_Logout, C_FindObjectsInit, C_FindObjects,
C_FindObjectsFinal, C_GetAttributeValue, C_GenerateRandom
```

Add crypto operations only if needed (e.g. `C_SignInit` / `C_Sign`).

## 9) Failure modes and diagnostics

- **No peer cert in enforce mode**: requests are denied.
- **Invalid or missing policy**: denies occur and logs include parse/load errors.
- **Unexpected hangs**: check server logs for `AUTHZ DENY` and add the missing
  function(s) to the policy.

## 10) Security considerations

- The daemon is the **trust boundary**. Treat it like an HSM proxy and harden
  it accordingly (firewall, limited admin access, monitoring).
- TLS verification must remain enabled in enforce mode to keep identity binding.
- Prefer fingerprint‑based matching over CN/SAN to avoid ambiguity.
