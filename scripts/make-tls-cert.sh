#!/usr/bin/env bash
# Generate the TLS material for the web UI: a local CA (once) and a server
# certificate signed by it, valid for the addresses the UI answers on.
#
#   scripts/make-tls-cert.sh                # names taken from .env + hostname
#   scripts/make-tls-cert.sh 10.0.0.246 tsf.lan
#
# Import certs/ca.crt into the browser or OS trust store once, on every machine
# that uses the UI, and the padlock is green from then on -- including after a
# re-run of this script, which reuses the CA and only reissues the server cert.
set -euo pipefail

cd "$(dirname "$0")/.."
dir=${TSF_CERT_DIR:-certs}
mkdir -p "$dir"

names=("$@")
if [ ${#names[@]} -eq 0 ]; then
  if [ -f .env ]; then
    addr=$(sed -n 's/^TSF_BIND_ADDR=//p' .env | tail -1)
    # 0.0.0.0 is a bind, not a name a certificate can assert.
    [ -n "${addr:-}" ] && [ "$addr" != "0.0.0.0" ] && names+=("$addr")
  fi
  names+=("$(hostname -f 2>/dev/null || hostname)")
fi

# localhost is always in: the container and the operator both reach it that way.
san="DNS:localhost,IP:127.0.0.1"
primary=""
for n in "${names[@]}"; do
  [ -n "$n" ] || continue
  [ -n "$primary" ] || primary=$n
  if [[ $n =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then san="$san,IP:$n"; else san="$san,DNS:$n"; fi
done
primary=${primary:-localhost}

if [ ! -f "$dir/ca.crt" ]; then
  echo "creating local CA in $dir/ca.crt (import this one in your browser)"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$dir/ca.key" -out "$dir/ca.crt" -days 3650 -sha256 \
    -subj "/CN=tsf-anonymizer local CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
fi

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$dir/server.key" -out "$dir/server.csr" -subj "/CN=$primary" 2>/dev/null
openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" \
  -CAcreateserial -out "$dir/server.crt" -days 825 -sha256 \
  -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san") 2>/dev/null
rm -f "$dir/server.csr" "$dir/ca.srl"

# The container runs as the host user and mounts this directory read-only.
chmod 600 "$dir/ca.key" "$dir/server.key"
chmod 644 "$dir/ca.crt" "$dir/server.crt"
echo "server certificate: $dir/server.crt"
echo "valid for: $san"
