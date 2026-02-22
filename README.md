# pkcs11-proxy (fork)

This fork provides a PKCS#11 proxy daemon and client module, with optional TLS
transport (PSK or mTLS) and a test suite based on SoftHSM2.

## Quick Start (Nix)

```sh
nix develop
cmake . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Tests

### 1) Prepare SoftHSM2 token

```sh
./tests/setup-softhsm2.sh
```

This script creates `tests/softhsm2.conf`, initializes a token named
`ProxyTestToken`, and creates an EC key used by the tests.
It also attempts to auto-detect the SoftHSM2 module path (including under Nix).

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

Use `tls://` in the socket URL and configure one of the following:

### TLS-PSK

```sh
PKCS11_PROXY_TLS_PSK_FILE=/path/to/psk-file
PKCS11_DAEMON_SOCKET=tls://127.0.0.1:2345
PKCS11_PROXY_SOCKET=tls://127.0.0.1:2345
```

### mTLS

```sh
PKCS11_PROXY_TLS_MODE=cert
PKCS11_PROXY_TLS_CERT_FILE=/path/to/cert.pem
PKCS11_PROXY_TLS_KEY_FILE=/path/to/key.pem
PKCS11_PROXY_TLS_CA_FILE=/path/to/ca.pem
PKCS11_PROXY_TLS_VERIFY_PEER=true
```

Provide the corresponding client/server certs and keys on each side.
