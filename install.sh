#!/usr/bin/env bash
set -euo pipefail

REPO="Furowu/brokre"
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

parse_brokre_version() {
    echo "$1" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1
}

INSTALLED_VER=""
if command -v brokre >/dev/null 2>&1; then
    INSTALLED_VER=$(parse_brokre_version "$(brokre --version 2>/dev/null || true)")
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
    URL="https://github.com/$REPO/releases/latest/download/brokre-$TARGET.tar.gz"
else
    TARGET_VER="${VERSION_ARG#v}"
    URL="https://github.com/$REPO/releases/download/v${TARGET_VER}/brokre-$TARGET.tar.gz"
fi

if [ -n "$INSTALLED_VER" ] && [ "$INSTALLED_VER" = "$TARGET_VER" ] && [ "${BROKRE_INSTALL_FORCE:-}" != "1" ]; then
    echo "brokre v$INSTALLED_VER already installed (up to date)."
    echo "Force reinstall: BROKRE_INSTALL_FORCE=1 curl -fsSL ... | bash"
    exit 0
fi

if [ -n "$INSTALLED_VER" ]; then
    echo "Upgrading brokre v$INSTALLED_VER → v$TARGET_VER for $TARGET..."
else
    echo "Installing brokre v$TARGET_VER for $TARGET..."
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "Downloading..."
curl -fsSL "$URL" -o "$TMPDIR/brokre.tar.gz"

echo "Extracting..."
tar -xzf "$TMPDIR/brokre.tar.gz" -C "$TMPDIR"

echo "Installing to $INSTALL_DIR..."
chmod +x "$TMPDIR/brokre"
mv "$TMPDIR/brokre" "$INSTALL_DIR/brokre"

echo "Verifying..."
brokre --version || true

if [ "$OS" = "darwin" ]; then
    echo
    echo "Note: On macOS brokre stores its master key in ~/.brokre/ (file-based)"
    echo "      instead of the OS Keychain to avoid authorization dialogs on"
    echo "      every run. Set BROKRE_USE_KEYCHAIN=1 if you prefer Keychain."
fi

echo "brokre installed successfully."

if [ -z "$INSTALLED_VER" ]; then
    echo
    echo "Opening credential manager (background)..."
    BROKRE_HOME="${HOME}/.brokre"
    mkdir -p "${BROKRE_HOME}"
    # Prevent a duplicate wizard if the user runs brokre immediately after install.
    touch "${BROKRE_HOME}/.onboard_spawned"
    if brokre manage --onboard --open & then
        sleep 2
        echo "If the browser did not open, check the URL printed above or run: brokre manage --onboard --open"
    else
        echo "Run: brokre manage --onboard --open"
    fi
fi
