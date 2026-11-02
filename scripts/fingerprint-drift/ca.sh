#!/usr/bin/env bash
# Make a throwaway CA and a leaf for localtest.me in <dir>; print the leaf's
# SPKI SHA-256 (base64), which Chrome takes in --ignore-certificate-errors-spki-list.
set -euo pipefail
dir=$1
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=fingerprint-drift CA" -keyout ca.key -out ca.pem \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localtest.me" -keyout leaf.key -out leaf.csr 2>/dev/null
printf 'subjectAltName=DNS:localtest.me\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile leaf.ext -out leaf.pem 2>/dev/null
cat leaf.pem ca.pem > chain.pem
openssl x509 -in leaf.pem -pubkey -noout | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | base64
