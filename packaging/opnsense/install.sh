#!/usr/bin/env bash
#
# One-shot helper to build + stage a FlexBraid OPNsense install.
# Run from the repo root on a box with Go.
#
# Prints the target paths; you still scp to the router (see README.md).
set -euo pipefail
cd "$(dirname "$0")/../.."

echo ">> cross-compiling freebsd/amd64"
GOOS=freebsd GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w" -o flexbraid-freebsd-amd64 ./cmd/flexbraid

echo ">> staging artifacts for the router"
mkdir -p staging
cp flexbraid-freebsd-amd64 packaging/opnsense/flexbraid.rc \
   packaging/opnsense/client.yaml.example staging/
echo ">> done. Copy to the router and install per packaging/opnsense/README.md"
echo "   scp staging/flexbraid-freebsd-amd64 root@<router>:/usr/local/bin/flexbraid"
echo "   scp staging/flexbraid.rc          root@<router>:/usr/local/etc/rc.d/flexbraid"
echo "   scp staging/client.yaml.example   root@<router>:/etc/flexbraid/client.yaml"
