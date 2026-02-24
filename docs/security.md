# Security Architecture

This document provides technical security details for the pkcs11-proxy
mTLS fork.

It supplements SECURITY.md, which describes reporting procedures and
supported versions.

------------------------------------------------------------------------

## TLS Stack

-   OpenSSL (`SSL_CTX`, `SSL`, `BIO`)
-   Minimum TLS version: 1.2
-   TLS-PSK limited to TLS 1.2
-   Certificate mode uses OpenSSL HIGH security defaults unless
    overridden.

PSK cipher suites:

-   TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
-   TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
-   TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256

------------------------------------------------------------------------

## Certificate Handling (mTLS)

Enabled with:

    PKCS11_PROXY_TLS_MODE=cert | mtls

Required:

-   PKCS11_PROXY_TLS_CERT_FILE
-   PKCS11_PROXY_TLS_KEY_FILE

Optional:

-   PKCS11_PROXY_TLS_CA_FILE
-   PKCS11_PROXY_TLS_CA_PATH
-   PKCS11_PROXY_TLS_CRL_FILE

Peer verification:

-   Enabled by default
-   Client verifies server identity
-   Server may require client certificates

Hostname verification:

-   SNI enabled
-   DNS/IP verified against tls:// endpoint

------------------------------------------------------------------------

## TLS‑PSK Handling

-   PSK files follow GnuTLS `psktool` format: `identity:hexkey`
-   Server selects keys by identity
-   Client uses first non-comment entry
-   Key material is never logged

------------------------------------------------------------------------

## Configuration Sources

-   Environment variables
-   Optional `/etc/pkcs11-proxy.conf`

Key settings:

-   PKCS11_PROXY_TLS_MODE
-   PKCS11_PROXY_TLS_PSK_FILE
-   PKCS11_PROXY_TLS_CERT_FILE
-   PKCS11_PROXY_TLS_KEY_FILE
-   PKCS11_PROXY_TLS_VERIFY_PEER

------------------------------------------------------------------------

## Threat Model

### In Scope

-   Network MITM and interception
-   Unauthorized remote connections
-   TLS secret compromise
-   Misconfiguration causing plaintext transport

### Assumptions

-   Underlying HSM security is trusted
-   Host OS is not compromised
-   Local privileged attackers are out of scope

------------------------------------------------------------------------

## Operational Guidance

-   Prefer `tls://` sockets over `tcp://`
-   Restrict filesystem permissions on key material
-   Use unique PSK identities per client
-   Keep OpenSSL updated

------------------------------------------------------------------------

## Cryptographic Dependencies

Runtime:

-   OpenSSL \>= 1.1.1

Development:

-   SoftHSM2
-   Python cryptography (tests)
