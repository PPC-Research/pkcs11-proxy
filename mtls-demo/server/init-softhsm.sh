#!/run/current-system/sw/bin/bash
set -euo pipefail

export PATH=/run/current-system/sw/bin:$PATH

export SOFTHSM2_CONF=${SOFTHSM2_CONF:-/etc/softhsm2.conf}
module_path="${SOFTHSM2_MODULE:-/run/current-system/sw/lib/softhsm/libsofthsm2.so}"

mkdir -p /var/lib/softhsm/tokens

show_slots() {
  timeout 5s softhsm2-util --show-slots 2>/dev/null || true
}

slots_output=$(show_slots)
if ! echo "$slots_output" | grep -Eq "Token label[[:space:]]*: ProxyTestToken"; then
  softhsm2-util --init-token --free --label ProxyTestToken --so-pin 1234 --pin 1234
fi

if pkcs11-tool --module "$module_path" --token-label ProxyTestToken \
  --login --pin 1234 --list-objects --type privkey 2>/dev/null | \
  grep -q "label: *ProxyTestExistingECKey"; then
  exit 0
fi

pkcs11-tool --module "$module_path" --token-label ProxyTestToken \
  --login --pin 1234 --keypairgen --key-type EC:prime256v1 \
  --label ProxyTestExistingECKey --id 01
