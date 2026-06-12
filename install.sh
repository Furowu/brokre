#!/usr/bin/env bash
set -euo pipefail

REPO="Furowu/brokr"
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

parse_brokr_version() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

INSTALLED_VER=""
if command -v brokr >/dev/null 2>&1; then
    INSTALLED_VER=$(parse_brokr_version "$(brokr --version 2>/dev/null || true)")
fi

VERSION_ARG=${1:-latest}
if [ "$VERSION_ARG" = "latest" ]; then
    TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
        | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": "v([^"]+)".*/\1/')
    if [ -z "$TAG" ]; then
        echo "Failed to resolve latest release from GitHub."
        exit 1
    fi
    TARGET_VER="$TAG"
    URL="https://github.com/$REPO/releases/latest/download/brokr-$TARGET.tar.gz"
else
    TARGET_VER="${VERSION_ARG#v}"
    URL="https://github.com/$REPO/releases/download/v${TARGET_VER}/brokr-$TARGET.tar.gz"
fi

if [ -n "$INSTALLED_VER" ] && [ "$INSTALLED_VER" = "$TARGET_VER" ] && [ "${BROKR_INSTALL_FORCE:-}" != "1" ]; then
    echo "brokr v$INSTALLED_VER already installed (up to date)."
    echo "Force reinstall: BROKR_INSTALL_FORCE=1 curl -fsSL ... | bash"
    exit 0
fi

if [ -n "$INSTALLED_VER" ]; then
    echo "Upgrading brokr v$INSTALLED_VER → v$TARGET_VER for $TARGET..."
else
    echo "Installing brokr v$TARGET_VER for $TARGET..."
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading..."
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

if [ -z "$INSTALLED_VER" ]; then
    echo
    echo "Opening credential manager (background)..."
    BROKR_HOME="${HOME}/.brokr"
    mkdir -p "${BROKR_HOME}"
    # Prevent a duplicate wizard if the user runs brokr immediately after install.
    touch "${BROKR_HOME}/.onboard_spawned"
    if brokr manage --onboard --open & then
        sleep 2
        echo "If the browser did not open, check the URL printed above or run: brokr manage --onboard --open"
    else
        echo "Run: brokr manage --onboard --open"
    fi
fi
