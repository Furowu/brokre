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
chmod +x "$TMPDIR/brokre"

USER_BIN="${HOME}/.brokre/bin"
PATH_MARKER="# brokre CLI (install.sh)"
PATH_LINE='export PATH="$HOME/.brokre/bin:$PATH"'

ensure_brokre_on_path() {
    local rc block
    block=$(printf '\n%s\n%s\n' "$PATH_MARKER" "$PATH_LINE")
    for rc in "${HOME}/.zprofile" "${HOME}/.zshrc" "${HOME}/.bash_profile" "${HOME}/.bashrc" "${HOME}/.profile"; do
        [[ -f "$rc" ]] || continue
        grep -q '.brokre/bin' "$rc" 2>/dev/null && return 0
    done
    for rc in "${HOME}/.zprofile" "${HOME}/.zshrc" "${HOME}/.bash_profile" "${HOME}/.bashrc" "${HOME}/.profile"; do
        if [[ -f "$rc" ]] && ! grep -qF "$PATH_MARKER" "$rc" 2>/dev/null; then
            printf '%s' "$block" >>"$rc"
            echo "brokre: added ~/.brokre/bin to PATH in $rc"
            echo "       open a new terminal (or: source $rc) for \`brokre manage\`."
            return 0
        fi
    done
    # no shell rc yet — create ~/.zshrc on macOS, ~/.bashrc elsewhere
    if [[ "$OS" == darwin ]]; then
        rc="${HOME}/.zshrc"
    else
        rc="${HOME}/.bashrc"
    fi
    printf '%s' "$block" >>"$rc"
    echo "brokre: added ~/.brokre/bin to PATH in $rc"
}

install_binary() {
  if mkdir -p "$INSTALL_DIR" 2>/dev/null && [[ -w "$INSTALL_DIR" ]]; then
    mv "$TMPDIR/brokre" "$INSTALL_DIR/brokre"
    echo "Installed to $INSTALL_DIR/brokre"
    rm -f "$USER_BIN/brokre" "$USER_BIN/brokr" 2>/dev/null || true
    return 0
  fi
  mkdir -p "$USER_BIN"
  mv "$TMPDIR/brokre" "$USER_BIN/brokre"
  rm -f "$USER_BIN/brokr" 2>/dev/null || true
  echo "Installed to $USER_BIN/brokre (no write access to $INSTALL_DIR)"
  ensure_brokre_on_path
}

install_binary

echo "Verifying..."
brokre --version || "$USER_BIN/brokre" --version || true

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
    if command -v brokre >/dev/null 2>&1 && brokre manage --onboard --open & then
        sleep 2
        echo "If the browser did not open, check the URL printed above or run: brokre manage --onboard --open"
    elif [[ -x "$USER_BIN/brokre" ]] && "$USER_BIN/brokre" manage --onboard --open & then
        sleep 2
        echo "If the browser did not open, check the URL printed above or run: brokre manage --onboard --open"
    else
        echo "Run: brokre manage --onboard --open"
    fi
fi
