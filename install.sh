#!/usr/bin/env bash
set -euo pipefail

REPO="brokr/brokr"
INSTALL_DIR="/usr/local/bin"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$OS" in
    linux)
        case "$ARCH" in
            x86_64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) echo "Unsupported arch: $ARCH"; exit 1 ;;
        esac
        ;;
    darwin)
        case "$ARCH" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64) TARGET="aarch64-apple-darwin" ;;
            *) echo "Unsupported arch: $ARCH"; exit 1 ;;
        esac
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

VERSION=${1:-latest}
if [ "$VERSION" = "latest" ]; then
    URL="https://github.com/$REPO/releases/latest/download/brokr-$TARGET.tar.gz"
else
    URL="https://github.com/$REPO/releases/download/$VERSION/brokr-$TARGET.tar.gz"
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading brokr for $TARGET..."
curl -fsSL "$URL" -o "$TMPDIR/brokr.tar.gz"

echo "Extracting..."
tar -xzf "$TMPDIR/brokr.tar.gz" -C "$TMPDIR"

echo "Installing to $INSTALL_DIR..."
chmod +x "$TMPDIR/brokr"
mv "$TMPDIR/brokr" "$INSTALL_DIR/brokr"

echo "Verifying..."
brokr --version || true

if [ "$OS" = "darwin" ]; then
    echo
    echo "Note: On macOS brokr stores its master key in ~/.brokr/ (file-based)"
    echo "      instead of the OS Keychain to avoid authorization dialogs on"
    echo "      every run. Set BROKR_USE_KEYCHAIN=1 if you prefer Keychain."
fi

echo "brokr installed successfully."
