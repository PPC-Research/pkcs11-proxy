# mTLS demo (NixOS containers)

This demo runs a pkcs11-proxy daemon backed by SoftHSM in one NixOS container
and a client container that connects via mTLS using the pkcs11-proxy module.
Both containers include tcpdump, tshark (wireshark-cli), and xxd for inspection.

## Contents

- `certs/` generated CA, server, and client certs/keys (not committed)
- `authz.example.json` per-client policy template (use `gen-authz.sh` to create `authz.json`)
- `nixos/` NixOS configs for server/client images
- `docker-compose.yml` demo topology
- `scripts/build-images.sh` build + load images with Nix

## Build and run

From repo root:

```sh
./mtls-demo/scripts/build-images.sh
cd mtls-demo
mkdir -p volumes/softhsm volumes/logs
./scripts/gen-certs.sh
./scripts/gen-authz.sh

docker compose up -d
```

`docker-compose.yml` bind-mounts:

- `./certs` → `/etc/mtls` (server + client certs/keys)
- `./authz.json` → `/etc/pkcs11-proxy/authz.json` (policy)

The compose file runs each container with `/init` and `privileged: true` so
systemd and NixOS services work as expected.

## Use the client

```sh
docker exec -it pkcs11-proxy-client /run/current-system/sw/bin/bash

# Enumerate slots/tokens via pkcs11-tool
pkcs11-proxy-enum

# Sign data using the SoftHSM key via OpenSSL + pkcs11-provider
pkcs11-proxy-sign "hello world"
```

To try a denied client, override the client certificate:

```sh
PKCS11_PROXY_TLS_CERT_FILE=/etc/mtls/clientB.crt \
PKCS11_PROXY_TLS_KEY_FILE=/etc/mtls/clientB.key \
pkcs11-proxy-sign "should be denied"
```

You should see an AUTHZ DENY in the server logs:

```sh
docker exec -it pkcs11-proxy-server journalctl -u pkcs11-daemon -n 50 --no-pager
```

## Policy guidance (avoid hangs)

Some tools (notably `pkcs11-tool`) loop on certain calls during enumeration
and login. If those calls are denied, the client can appear to “hang”.
When that happens, check logs and add the missing functions to the policy.

Common enumeration/login functions to allow:

```
C_Initialize, C_Finalize, C_GetInfo, C_GetSlotList, C_GetSlotInfo,
C_GetTokenInfo, C_GetMechanismList, C_OpenSession, C_CloseSession,
C_GetSessionInfo, C_Login, C_Logout, C_FindObjectsInit, C_FindObjects,
C_FindObjectsFinal, C_GetAttributeValue, C_GenerateRandom
```

This demo’s policy is updated via:

```sh
./mtls-demo/scripts/host-fix-authz.sh
```

## Troubleshooting

- **Images not found / compose tries to pull**  
  Run `./mtls-demo/scripts/build-images.sh` from repo root and confirm:  
  `docker images | grep pkcs11-proxy`

- **`systemctl` or `bash` not found in container**  
  Use full paths:  
  `docker exec -it pkcs11-proxy-server /run/current-system/sw/bin/systemctl ...`  
  `docker exec -it pkcs11-proxy-client /run/current-system/sw/bin/bash`

- **`pkcs11-proxy-enum` missing**  
  The command is installed into the system profile. If it’s missing, rebuild images.
  As a fallback, run `/etc/pkcs11-proxy/enum.sh` directly.

- **Connection refused / `CKR_DEVICE_ERROR`**  
  The daemon is not listening. Check status:  
  `docker exec -it pkcs11-proxy-server /run/current-system/sw/bin/systemctl status pkcs11-daemon --no-pager`

- **TLS verify failed / bad certificate**  
  The server cert SAN must match the hostname in `PKCS11_PROXY_SOCKET`.  
  For this demo, use `tls://pkcs11-server:4511` (SAN includes `pkcs11-server`), or
  add a `/etc/hosts` entry mapping `pkcs11-server` to the server IP.

- **Authz policy failed to load**  
  Check:  
  `docker exec -it pkcs11-proxy-server /run/current-system/sw/bin/journalctl -u pkcs11-daemon -n 50 --no-pager -l`  
  A malformed JSON file will disable policy parsing and cause denies.
- **Follow deny logs in real time**  
  `./mtls-demo/scripts/server-tail.sh pkcs11-proxy-server 200 deny`

## Traffic capture

From either container:

```sh
# On the server, capture TLS traffic
sudo tcpdump -i any -nn -s0 -w /tmp/mtls.pcap port 4511

# Or use tshark for a quick summary
sudo tshark -i any -f "tcp port 4511" -V
```

Then copy the capture out:

```sh
docker cp pkcs11-proxy-server:/tmp/mtls.pcap ./mtls.pcap
```

### Decrypt mTLS traffic with SSL key log

To decrypt TLS in Wireshark/tshark you need a key log file from the client.
OpenSSL only writes it if you either set `SSLKEYLOGFILE` **or** pass
`-keylogfile` explicitly.

1) Run the capture on the server:

```sh
./mtls-demo/scripts/server-capture.sh pkcs11-proxy-server ./pkcs11-proxy.pcap
```

2) From the client container, run an OpenSSL handshake and write a key log:

```sh
docker exec -it pkcs11-proxy-client /run/current-system/sw/bin/bash -lc '
  export SSLKEYLOGFILE=/tmp/sslkeys.log
  openssl s_client -connect pkcs11-server:4511 \
    -cert /etc/mtls/clientA.crt \
    -key /etc/mtls/clientA.key \
    -CAfile /etc/mtls/ca.crt \
    -tls1_3 -keylogfile /tmp/sslkeys.log < /dev/null
  ls -l /tmp/sslkeys.log
'
```

3) Copy the key log to the host:

```sh
docker cp pkcs11-proxy-client:/tmp/sslkeys.log ./sslkeys.log
```

4) Decrypt with tshark on the host:

```sh
tshark -r ./pkcs11-proxy.pcap \
  -o tls.keylog_file:./sslkeys.log \
  -Y "tls.handshake" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.type -e tls.handshake.ciphersuite
```

Or open the pcap in Wireshark and set:
`Preferences → Protocols → TLS → (Pre)-Master-Secret log filename` to `sslkeys.log`.

## Notes

- The daemon listens on `tls://0.0.0.0:4511` inside the server container.
- SoftHSM tokens are stored in `mtls-demo/volumes/softhsm` on the host.
- The server enforces `authz.json` and requires verified client certificates.
- Certificates live in `/etc/mtls` inside both containers.
