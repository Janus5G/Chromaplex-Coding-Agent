#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="0.4.0"
ARCH="all"
PKGROOT="${TMPDIR:-/tmp}/chromaplex-coding-agent-debbuild"
OUT="${ROOT}/dist"
rm -rf "$PKGROOT"
mkdir -p "$PKGROOT/DEBIAN" "$PKGROOT/opt/chromaplex-coding-agent" "$PKGROOT/usr/bin" "$PKGROOT/usr/share/applications" "$OUT"
chmod 0755 "$PKGROOT" "$PKGROOT/DEBIAN" "$PKGROOT/opt" "$PKGROOT/opt/chromaplex-coding-agent" "$PKGROOT/usr" "$PKGROOT/usr/bin" "$PKGROOT/usr/share" "$PKGROOT/usr/share/applications"

cat > "$PKGROOT/DEBIAN/control" <<EOF
Package: chromaplex-coding-agent
Version: ${VERSION}
Section: devel
Priority: optional
Architecture: ${ARCH}
Maintainer: Janus Rokkjær
Depends: python3, python3-pyside6.qtcore, python3-pyside6.qtgui, python3-pyside6.qtwidgets, bubblewrap, coreutils, clamav
Recommends: python3-pyside6.qtwebenginewidgets, libsecret-tools, gcc, make, clamav-freshclam, wabt, apparmor, apparmor-utils, cryptsetup-bin
Description: Secure standalone coding agent with ChromaPlex CPL/CPA support
 Multi-mode Linux desktop application for generating, editing, previewing,
 running and exporting Linux, Windows, Web and ChromaPlex source projects.
 Includes a fail-closed Secure Compile Gate with local malware scanning,
 quarantine builds and SHA-256 security manifests.
EOF

cp -a "$ROOT/chromaplex_agent" "$PKGROOT/opt/chromaplex-coding-agent/"
find "$PKGROOT/opt/chromaplex-coding-agent" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$PKGROOT/opt/chromaplex-coding-agent" -type f -name '*.py[co]' -delete
cp "$ROOT/LICENSE" "$ROOT/THIRD_PARTY_SOURCES.md" "$ROOT/README.md" "$ROOT/TEST_REPORT.md" "$ROOT/CHROMAPRESS_IMPORT.md" "$ROOT/SECURITY.md" "$ROOT/SECURE_COMPILE_GATE.md" "$ROOT/HARDENING.md" "$ROOT/RELEASE_NOTES_v0.4.0.md" "$PKGROOT/opt/chromaplex-coding-agent/"
cp -a "$ROOT/hardening" "$PKGROOT/opt/chromaplex-coding-agent/"
# Seal installed application payload. The manifest intentionally excludes itself.
(
  cd "$PKGROOT/opt/chromaplex-coding-agent"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)

cat > "$PKGROOT/usr/bin/chromaplex-coding-agent" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="/opt/chromaplex-coding-agent"
cd "$APP_ROOT"
if ! sha256sum -c SHA256SUMS --quiet; then
  echo "Chromaplex Coding Agent: SHA-256 integrity verification FAILED. Refusing to start." >&2
  exit 126
fi
export PYTHONPATH="$APP_ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m chromaplex_agent "$@"
EOF
chmod 0755 "$PKGROOT/usr/bin/chromaplex-coding-agent"
cat > "$PKGROOT/usr/bin/chromaplex-verify-build" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="/opt/chromaplex-coding-agent"
cd "$APP_ROOT"
if ! sha256sum -c SHA256SUMS --quiet; then
  echo "Chromaplex Coding Agent: installed SHA-256 integrity verification FAILED." >&2
  exit 126
fi
export PYTHONPATH="$APP_ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m chromaplex_agent.verify_build "$@"
EOF
chmod 0755 "$PKGROOT/usr/bin/chromaplex-verify-build"
cat > "$PKGROOT/usr/bin/chromaplex-hardening" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_ROOT="/opt/chromaplex-coding-agent"
cd "$APP_ROOT"
if ! sha256sum -c SHA256SUMS --quiet; then
  echo "Chromaplex Coding Agent: installed SHA-256 integrity verification FAILED." >&2
  exit 126
fi
export PYTHONPATH="$APP_ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m chromaplex_agent.hardening "$@"
EOF
chmod 0755 "$PKGROOT/usr/bin/chromaplex-hardening"
cp "$ROOT/packaging/chromaplex-coding-agent.desktop" "$PKGROOT/usr/share/applications/"
chmod 0644 "$PKGROOT/usr/share/applications/chromaplex-coding-agent.desktop"
find "$PKGROOT/opt/chromaplex-coding-agent" -type f -exec chmod 0644 {} +
find "$PKGROOT/opt/chromaplex-coding-agent" -type d -exec chmod 0755 {} +
find "$PKGROOT" -type d -exec chmod g-s {} +
DEB="$OUT/chromaplex-coding-agent_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owner-group --build "$PKGROOT" "$DEB"
(cd "$OUT" && sha256sum "$(basename "$DEB")" > "$(basename "$DEB").sha256")
echo "$DEB"
