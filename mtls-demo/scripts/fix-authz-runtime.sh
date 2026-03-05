#!/run/current-system/sw/bin/bash
set -euo pipefail

FP=$(openssl x509 -in /etc/mtls/clientA.crt -noout -fingerprint -sha256 | sed 's/.*=//' | tr -d ':' | tr 'A-F' 'a-f')

printf '{"version":1,"default":"deny","clients":[{"id_type":"cert_fingerprint_sha256","id":"%s","allow":{"pkcs11_functions":["C_Initialize","C_Finalize","C_GetInfo","C_GetSlotList","C_GetSlotInfo","C_GetTokenInfo","C_OpenSession","C_CloseSession","C_Login","C_Logout","C_FindObjectsInit","C_FindObjects","C_FindObjectsFinal","C_GetAttributeValue","C_SignInit","C_Sign"],"tokens":["ProxyTestToken"],"objects":["ProxyTestExistingECKey"]}}]}\n' "$FP" > /run/authz.json

/run/current-system/sw/bin/systemctl set-environment PKCS11_PROXY_AUTHZ_FILE=/run/authz.json
/run/current-system/sw/bin/systemctl set-environment PKCS11_PROXY_AUTHZ_MODE=enforce
/run/current-system/sw/bin/systemctl restart pkcs11-daemon

/run/current-system/sw/bin/journalctl -u pkcs11-daemon -n 5 --no-pager -l
