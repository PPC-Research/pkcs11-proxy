# PKCS#11 Proxy + NetHSM Setup Guide

This document describes how to configure:

1.  The **Daemon (host connected to NetHSM)**
2.  **Remote Clients (VMs)**
3.  An example **Authorization Policy** for multiple VMs

------------------------------------------------------------------------

## 1) Daemon (Host Connected to NetHSM)

### Configure TLS + Authorization

``` bash
# TLS Configuration
export PKCS11_DAEMON_SOCKET=tls://0.0.0.0:2345
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE=/etc/pkcs11-proxy/server.crt
export PKCS11_PROXY_TLS_KEY_FILE=/etc/pkcs11-proxy/server.key
export PKCS11_PROXY_TLS_CA_FILE=/etc/pkcs11-proxy/ca.crt
export PKCS11_PROXY_TLS_VERIFY_PEER=true

# Authorization Configuration
export PKCS11_PROXY_AUTHZ_MODE=enforce   # Use 'audit' during rollout if needed
export PKCS11_PROXY_AUTHZ_FILE=/etc/pkcs11-proxy/authz.json
export PKCS11_PROXY_AUTHZ_DEFAULT=deny

# Optional: Enable debug logging
# export PKCS11_PROXY_AUTHZ_LOG_LEVEL=debug
```

### Start the Daemon

``` bash
./pkcs11-daemon /path/to/netHSM-pkcs11.so
```

------------------------------------------------------------------------

## 2) Clients (Remote VMs)

Each VM must use its **own client certificate and key**.

### Configure TLS on Each VM

``` bash
export PKCS11_PROXY_SOCKET=tls://host.example.com:2345
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE=/etc/pkcs11-proxy/client.crt
export PKCS11_PROXY_TLS_KEY_FILE=/etc/pkcs11-proxy/client.key
export PKCS11_PROXY_TLS_CA_FILE=/etc/pkcs11-proxy/ca.crt
export PKCS11_PROXY_TLS_VERIFY_PEER=true
```

### PKCS#11 Module Usage

Use:

-   `libpkcs11-proxy.so` as the PKCS#11 module\
    **OR**
-   Configure via OpenSSL `pkcs11-provider`

------------------------------------------------------------------------

## 3) Example Authorization Policy (Multiple VMs)

Below is an example `authz.json` policy file:

``` json
{
  "version": 1,
  "default": "deny",
  "clients": [
    {
      "id_type": "cert_fingerprint_sha256",
      "id": "ab12...ff",
      "allow": {
        "pkcs11_functions": [
          "C_Initialize",
          "C_Finalize",
          "C_GetInfo",
          "C_GetSlotList",
          "C_GetSlotInfo",
          "C_GetTokenInfo",
          "C_OpenSession",
          "C_CloseSession",
          "C_Login",
          "C_Logout",
          "C_FindObjectsInit",
          "C_FindObjects",
          "C_FindObjectsFinal",
          "C_GetAttributeValue",
          "C_SignInit",
          "C_Sign"
        ],
        "tokens": ["NetHSM-Prod"],
        "objects": ["SigningKey-*"]
      }
    },
    {
      "id_type": "subject_cn",
      "id": "jenkins-runner-*",
      "allow": {
        "pkcs11_functions": [
          "C_Initialize",
          "C_Finalize",
          "C_GetInfo",
          "C_GetSlotList",
          "C_GetSlotInfo",
          "C_GetTokenInfo",
          "C_OpenSession",
          "C_CloseSession"
        ],
        "tokens": ["NetHSM-Prod"]
      }
    }
  ]
}
```

------------------------------------------------------------------------

## Notes

-   The default policy is set to **deny**, following the principle of
    least privilege.
-   Use `audit` mode before switching to `enforce` in production.
-   Ensure all certificates are signed by the trusted CA configured via
    `PKCS11_PROXY_TLS_CA_FILE`.
