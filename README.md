# pkcs11-proxy (fork)

This fork provides a PKCS#11 proxy daemon and client module, with optional TLS
transport (PSK or mTLS) and a test suite based on SoftHSM2.

## Quick Start (Nix)

```sh
nix develop
cmake . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Documentation

- `usecases.md` — real‑world scenarios and test mapping
- `docs/ARCHITECTURE.md` — internal design and request flow
- `docs/test-coverage.md` — coverage matrix with test links
- `docs/per-client-identity.md` — per‑client authz details
- `docs/security.md` — security notes
- `mtls-demo/README.md` — NixOS mTLS demo
- `SECURITY.md` — security policy
- `TODO.md` — project roadmap

## Tests

### 1) Prepare SoftHSM2 token

```sh
./tests/setup-softhsm2.sh
```

This script creates `tests/softhsm2.conf`, initializes a token named
`ProxyTestToken`, and creates an EC key used by the tests. It also attempts
to auto-detect the SoftHSM2 module path (including under Nix).

### 2) Run tests

Plain TCP:

```sh
pytest -q tests/test_pkcs11_proxy.py
```

TLS-PSK:

```sh
PKCS11_TEST_TLS=1 pytest -q tests/test_pkcs11_proxy.py
```

mTLS:

```sh
PKCS11_TEST_MTLS=1 pytest -q tests/test_pkcs11_proxy.py
```

Notes:
- Set `PKCS11_TEST_LIB=/path/to/libsofthsm2.so` if SoftHSM is not in the default paths.
- Set `PKCS11_TEST_NO_PROXY=1` to run against SoftHSM directly (no daemon/proxy).
- Set `PKCS11_TEST_NO_DAEMON=1` to skip starting the daemon (useful for debugging).

## TLS Configuration (runtime)

Use `tls://` in the socket URL and configure one of the following.

### TLS-PSK

```sh
PKCS11_PROXY_TLS_PSK_FILE=/path/to/psk-file
PKCS11_DAEMON_SOCKET=tls://127.0.0.1:2345
PKCS11_PROXY_SOCKET=tls://127.0.0.1:2345
```

### mTLS (basic setup)

You need a CA, plus a server cert/key and a client cert/key. Example with OpenSSL:

```sh
# CA
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -days 365 -subj "/CN=pkcs11-proxy-ca" -out ca.crt

# Server key/cert (adjust CN/SAN as needed)
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=pkcs11-proxy-server" -out server.csr
printf "subjectAltName=DNS:server.example.com,IP:127.0.0.1\n" > san.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out server.crt -extfile san.cnf

# Client key/cert
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=pkcs11-proxy-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 365 -out client.crt
```

#### Server (daemon) configuration

```sh
export PKCS11_DAEMON_SOCKET=tls://server.example.com:2345
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE=/path/to/server.crt
export PKCS11_PROXY_TLS_KEY_FILE=/path/to/server.key
export PKCS11_PROXY_TLS_CA_FILE=/path/to/ca.crt
export PKCS11_PROXY_TLS_VERIFY_PEER=true

./build/pkcs11-daemon /path/to/libsofthsm2.so
```

#### Client (proxy module) configuration

```sh
export PKCS11_PROXY_SOCKET=tls://server.example.com:2345
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE=/path/to/client.crt
export PKCS11_PROXY_TLS_KEY_FILE=/path/to/client.key
export PKCS11_PROXY_TLS_CA_FILE=/path/to/ca.crt
export PKCS11_PROXY_TLS_VERIFY_PEER=true
```

Then use `libpkcs11-proxy.so` as your PKCS#11 module.

## Authorization (mTLS client identity)

When mTLS is enabled and peer verification is enabled, the daemon can enforce a
per-client authorization policy based on the authenticated client certificate.

Environment variables:

- `PKCS11_PROXY_AUTHZ_FILE=/path/to/authz.json` (required for enforce/audit)
- `PKCS11_PROXY_AUTHZ_MODE=disabled|enforce|audit` (default: disabled)
  - `disabled`: no authz checks
  - `enforce`: deny operations not explicitly allowed
  - `audit`: allow operations but log what would be denied
- `PKCS11_PROXY_AUTHZ_DEFAULT=deny|allow` (default: deny when enforce/audit is active)
- `PKCS11_PROXY_AUTHZ_LOG_LEVEL=info|debug` (optional, default: info)

Notes:
- In `enforce` mode, the daemon will deny requests if no verified peer
  certificate is available (for example when `PKCS11_PROXY_TLS_VERIFY_PEER=false`).
- Authorization is enforced server-side before forwarding requests to the
  underlying PKCS#11 module.
 - For a deeper internal overview, see `docs/ARCHITECTURE.md`.

Troubleshooting:
- `CKR_GENERAL_ERROR` on `C_Initialize`: check daemon logs for `AUTHZ DENY` to
  confirm policy is blocking the call.
- `AUTHZ: failed to load policy file`: verify the file exists in the daemon
  environment and the JSON is valid.
- TLS verify errors: ensure the client connects using a hostname that matches
  the server certificate SAN.
- Enumeration or login hangs: check daemon logs for repeated `AUTHZ DENY` lines
  and add the missing PKCS#11 functions to the allow list (common ones include
  `C_GetSessionInfo`, `C_GetMechanismList`, and `C_GenerateRandom`).

### Policy format (JSON)

Example `authz.json`:

```json
{
  "version": 1,
  "default": "deny",
  "clients": [
    {
      "id_type": "cert_fingerprint_sha256",
      "id": "ab12...ff",
      "allow": {
        "pkcs11_functions": [
          "C_Initialize","C_Finalize","C_GetInfo","C_GetSlotList","C_GetSlotInfo",
          "C_GetTokenInfo","C_OpenSession","C_CloseSession","C_Login","C_Logout",
          "C_FindObjectsInit","C_FindObjects","C_FindObjectsFinal",
          "C_GetAttributeValue","C_SignInit","C_Sign"
        ],
        "tokens": ["ProxyTestToken"],
        "objects": ["ProxyTestExistingECKey","LeafKey-*"]
      }
    },
    {
      "id_type": "subject_cn",
      "id": "jenkins-prod-runner-*",
      "allow": {
        "pkcs11_functions": [
          "C_Initialize","C_Finalize","C_GetInfo","C_GetSlotList","C_GetSlotInfo",
          "C_GetTokenInfo","C_OpenSession","C_CloseSession","C_Login","C_Logout"
        ],
        "tokens": ["ProxyTestToken"]
      }
    }
  ]
}
```

Matching rules:
- `cert_fingerprint_sha256`: exact match (preferred)
- `subject_cn`: glob match on subject CN
- `san_uri`: glob match on SAN URI entries
- If multiple entries match, their `allow` rules are unioned.
- If no entry matches, the policy `default` applies.

## OpenSSL 3 provider (client-side)

If you want to use the proxy with OpenSSL 3, load a PKCS#11 provider and point
it at `libpkcs11-proxy.so`.

1) Install a PKCS#11 provider for OpenSSL 3 (for example, `pkcs11-provider`).
2) Create a config file like this:

```ini
# openssl-pkcs11.cnf
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
# Path to the provider module
module = /path/to/pkcs11-provider.so
# Path to the PKCS#11 module (the proxy client library)
pkcs11-module = /path/to/libpkcs11-proxy.so
activate = 1
```

3) Set env vars and use OpenSSL:

```sh
export OPENSSL_CONF=/path/to/openssl-pkcs11.cnf
export OPENSSL_MODULES=/path/to/openssl/modules

# Proxy TLS settings (mTLS example)
export PKCS11_PROXY_SOCKET=tls://server.example.com:2345
export PKCS11_PROXY_TLS_MODE=cert
export PKCS11_PROXY_TLS_CERT_FILE=/path/to/client.crt
export PKCS11_PROXY_TLS_KEY_FILE=/path/to/client.key
export PKCS11_PROXY_TLS_CA_FILE=/path/to/ca.crt
export PKCS11_PROXY_TLS_VERIFY_PEER=true
```

### Sign and verify data via PKCS#11

List objects (example using OpenSC tools):

```sh
pkcs11-tool --module /path/to/libpkcs11-proxy.so -O
```

Sign data with a private key stored in the token:

```sh
printf "hello" > data.txt

openssl pkeyutl -sign -rawin -digest sha256 -provider pkcs11 -provider default \
  -inkey "pkcs11:token=ProxyTestToken;object=ProxyTestExistingECKey;type=private" \
  -in data.txt -out sig.bin
```

Verify using the public key in the token:

```sh
openssl pkeyutl -verify -rawin -digest sha256 -provider pkcs11 -provider default \
  -inkey "pkcs11:token=ProxyTestToken;object=ProxyTestExistingECKey;type=public" \
  -in data.txt -sigfile sig.bin
```

Notes:
- Replace the PKCS#11 URI with the actual token/object label and key type.
- Some provider builds require `PKCS11_MODULE=/path/to/libpkcs11-proxy.so` instead
  of `pkcs11-module` in the config; if so, set the env var accordingly.
