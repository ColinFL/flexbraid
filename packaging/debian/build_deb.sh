#!/usr/bin/env bash
#
# Build a Debian/Ubuntu .deb for FlexBraid server.
#
# Usage (from the repo root, on Linux or in WSL/git-bash with dpkg-deb):
#   packaging/debian/build_deb.sh [version]
#
# Produces:  dist/flexbraid_<version>_amd64.deb
# Installs:  /usr/local/bin/flexbraid, /lib/systemd/system/flexbraid.service,
#            /etc/flexbraid/server.yaml (example, PSK placeholder), plus a
#            postinst that enables + starts the service.
#
# The config ships with a placeholder crypto.key — you MUST edit
# /etc/flexbraid/server.yaml before first real use.
set -euo pipefail

cd "$(dirname "$0")/../.."              # repo root
VERSION="${1:-0.1.0-m5}"
ARCH=amd64
PKG_NAME="flexbraid_${VERSION}_${ARCH}"
STAGE="$(mktemp -d)/${PKG_NAME}"
mkdir -p "${STAGE}/usr/local/bin" \
         "${STAGE}/lib/systemd/system" \
         "${STAGE}/etc/flexbraid" \
         "${STAGE}/var/log/flexbraid" \
         "${STAGE}/DEBIAN"

echo ">> cross-compiling ${GOOS:=linux} ${GOARCH:=amd64}"
GOOS="${GOOS}" GOARCH="${GOARCH}" go build -trimpath \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o "${STAGE}/usr/local/bin/flexbraid" ./cmd/flexbraid

echo ">> assembling package"
cp packaging/debian/flexbraid.service "${STAGE}/lib/systemd/system/"
cp packaging/debian/server.yaml.example "${STAGE}/etc/flexbraid/server.yaml"

cat > "${STAGE}/DEBIAN/control" <<EOF
Package: flexbraid
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libc6 (>= 2.34)
Maintainer: ColinFL <colinfl@users.noreply.github.com>
Description: Multi-WAN bonding tunnel with adaptive FEC
 FlexBraid weaves several WANs into one logical link so an inner VPN
 (WireGuard) sees a single stable connection. Includes per-WAN health
 monitoring, load balancing, cross-path FEC, telemetry and runtime reload.
EOF

cat > "${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if [ -f /etc/flexbraid/server.yaml ]; then
  chmod 600 /etc/flexbraid/server.yaml
fi
systemctl daemon-reload >/dev/null 2>&1 || true
# Only auto-start if the operator has sized the config (key != placeholder).
if grep -q "change-me" /etc/flexbraid/server.yaml 2>/dev/null; then
  echo "flexbraid: edit /etc/flexbraid/server.yaml (set crypto.key) then:"
  echo "  systemctl enable --now flexbraid"
else
  systemctl enable --now flexbraid >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "${STAGE}/DEBIAN/postinst"

echo ">> building .deb"
dpkg-deb --build --root-owner-group "${STAGE}" "dist/${PKG_NAME}.deb"

echo ">> done: dist/${PKG_NAME}.deb"
echo "   install on the server: dpkg -i dist/${PKG_NAME}.deb"
