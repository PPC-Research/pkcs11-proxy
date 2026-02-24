# Transport-Layer Code Review -- Development Record (2026-01)

This document records a focused **internal engineering review** of the
TLS/mTLS transport implementation introduced in this fork of
pkcs11-proxy.

## Context

The review was performed during active development prior to public
release, with the goal of validating OpenSSL usage, peer verification
behavior, error handling, and downgrade resistance.

## Scope

-   TLS and mTLS transport layer
-   PSK and certificate authentication paths
-   Connection lifecycle and cleanup logic

This document is retained for **engineering transparency and historical
context**. It does **not** imply vulnerabilities in upstream
pkcs11-proxy, and reflects issues identified while developing the new
transport layer.

All findings listed below are resolved unless explicitly stated
otherwise.

------------------------------------------------------------------------

## Review Findings (Historical)

Below are the findings ordered by severity, with file/line refs.

(CONTENT PRESERVED VERBATIM FROM ORIGINAL REVIEW)

Critical \[mTLS\]: TLS client does not perform hostname verification or
set SNI... High \[mTLS+PSK\]: TLS enforcement can silently downgrade to
plaintext... High \[mTLS+PSK\]: TLS connection failure leaks
resources... Medium \[PSK\]: PSK client identity auto-detection issue...
Medium \[mTLS+PSK\]: gck_rpc_set_string truncation... Medium
\[mTLS+PSK\]: SSL_ERROR_WANT_READ/WRITE handling... Low \[mTLS+PSK\]:
parse_argument NULL handling...

(All findings marked as Resolved in current implementation.)

------------------------------------------------------------------------

## Notes

-   Findings were discovered proactively during development.
-   Fixes were applied before production deployment.
-   The PKCS#11 protocol behavior remains compatible with upstream
    design.
