#!/bin/sh
# Install Universal Dev Security for the current user (Linux/macOS, no root).
# Creates ~/.local/share/uds/venv and installs UDS from a wheel (verified against
# SHA256SUMS when present) or a pip specification. Does not install scanners and
# does not modify shell profiles.
#
#   sh scripts/install.sh --wheel dist/1.0.0rc1/universal_dev_security-1.0.0rc1-py3-none-any.whl
#   sh scripts/install.sh --spec universal-dev-security==1.0.0rc1
set -eu

WHEEL=""
SPEC=""
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/uds"
while [ $# -gt 0 ]; do
  case "$1" in
    --wheel) WHEEL="$2"; shift 2 ;;
    --spec) SPEC="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ -n "$WHEEL" ] || [ -n "$SPEC" ] || { echo "Provide --wheel PATH or --spec SPEC" >&2; exit 2; }

PYTHON=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
    PYTHON="$candidate"; break
  fi
done
[ -n "$PYTHON" ] || { echo "Python 3.11 or newer is required." >&2; exit 1; }

if [ -n "$WHEEL" ]; then
  SUMS="$(dirname "$WHEEL")/SHA256SUMS"
  NAME="$(basename "$WHEEL")"
  if [ -f "$SUMS" ]; then
    EXPECTED="$(grep " $NAME\$" "$SUMS" | awk '{print $1}')"
    if command -v sha256sum >/dev/null 2>&1; then ACTUAL="$(sha256sum "$WHEEL" | awk '{print $1}')"
    else ACTUAL="$(shasum -a 256 "$WHEEL" | awk '{print $1}')"; fi
    [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || { echo "Checksum verification failed for $NAME" >&2; exit 1; }
    echo "Checksum verified: $NAME"
  else
    echo "Warning: no SHA256SUMS next to the wheel; integrity was not verified." >&2
  fi
fi

"$PYTHON" -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip >/dev/null
if [ -n "$WHEEL" ]; then "$INSTALL_DIR/venv/bin/python" -m pip install --upgrade "$WHEEL"
else "$INSTALL_DIR/venv/bin/python" -m pip install --upgrade "$SPEC"; fi
"$INSTALL_DIR/venv/bin/uds" --version
echo "Installed. Add to PATH, e.g.:  export PATH=\"$INSTALL_DIR/venv/bin:\$PATH\""
echo "Next: install scanners from their official sources, then run 'uds doctor'."
