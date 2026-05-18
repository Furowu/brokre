#!/usr/bin/env bash
set -euo pipefail

echo "[r] Building brokr release..."
cargo build --release

echo "[r] Installing to ~/.cargo/bin/brokr..."
cp target/release/brokr "$HOME/.cargo/bin/brokr"
chmod +x "$HOME/.cargo/bin/brokr"

# Also try /usr/local/bin if we have write access
if [ -w /usr/local/bin ]; then
    echo "[r] Installing to /usr/local/bin/brokr..."
    cp target/release/brokr /usr/local/bin/brokr
    chmod +x /usr/local/bin/brokr
fi

echo "[r] Code-signing for macOS..."
codesign -s - -f "$HOME/.cargo/bin/brokr" 2>/dev/null || true

if [ -w /usr/local/bin ]; then
    codesign -s - -f /usr/local/bin/brokr 2>/dev/null || true
fi

echo "[r] Verifying..."
brokr --version 2>/dev/null || true

echo "[r] Done ✓"
