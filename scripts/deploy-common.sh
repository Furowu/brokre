#!/usr/bin/env bash
# Shared helpers for ./d (deploy) — sourced, not executed directly.
set -euo pipefail

DEPLOY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION_FILE="$DEPLOY_ROOT/VERSION"
CARGO_TOML="$DEPLOY_ROOT/Cargo.toml"
MCP_PKG="$DEPLOY_ROOT/packages/brokr-mcp/package.json"
HOMEBREW_RB="$DEPLOY_ROOT/homebrew/brokr.rb"
HOMEBREW_TAP_DIR="${HOMEBREW_TAP_DIR:-$DEPLOY_ROOT/../homebrew-brokr}"
HOMEBREW_TAP_REMOTE="${HOMEBREW_TAP_REMOTE:-git@github.com:Furowu/homebrew-brokr.git}"
HOMEBREW_RELEASE_BASE="${HOMEBREW_RELEASE_BASE:-https://github.com/Furowu/brokr/releases/download}"
MCP_DIR="$DEPLOY_ROOT/packages/brokr-mcp"
DIST_DIR="$DEPLOY_ROOT/dist"

# Release targets (match .github/workflows/release.yml).
RELEASE_TARGETS=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-pc-windows-msvc
)

# Homebrew formula targets (RELEASE_TARGETS minus Windows).
HOMEBREW_TARGETS=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
)

# Default remotes (override in .deploy.env)
GITHUB_REMOTE="${GITHUB_REMOTE:-origin}"
GITEE_REMOTE="${GITEE_REMOTE:-gitee}"
GITHUB_URL="${GITHUB_URL:-https://github.com/Furowu/brokr.git}"
GITEE_URL="${GITEE_URL:-https://gitee.com/furowu/brokr.git}"
GITEE_BRANCH="${GITEE_BRANCH:-main}"

# Patterns that must never appear in publish artifacts.
SENSITIVE_NAMES=(
  .env
  .env.local
  .master_kek
  .audit_hmac
  hosts
  .brokr
)

log() { printf '[d] %s\n' "$*"; }
die() { printf '[d] ERROR: %s\n' "$*" >&2; exit 1; }

load_deploy_env() {
  local f="$DEPLOY_ROOT/.deploy.env"
  if [[ -f "$f" ]]; then
    # shellcheck disable=SC1090
    set -a && source "$f" && set +a
    log "loaded .deploy.env"
  fi
  GITHUB_REMOTE="${GITHUB_REMOTE:-origin}"
  GITEE_REMOTE="${GITEE_REMOTE:-gitee}"
  GITHUB_URL="${GITHUB_URL:-https://github.com/Furowu/brokr.git}"
  GITEE_URL="${GITEE_URL:-https://gitee.com/furowu/brokr.git}"
  GITEE_BRANCH="${GITEE_BRANCH:-main}"
  HOMEBREW_TAP_DIR="${HOMEBREW_TAP_DIR:-$DEPLOY_ROOT/../homebrew-brokr}"
  HOMEBREW_TAP_REMOTE="${HOMEBREW_TAP_REMOTE:-git@github.com:Furowu/homebrew-brokr.git}"
  HOMEBREW_RELEASE_BASE="${HOMEBREW_RELEASE_BASE:-https://github.com/Furowu/brokr/releases/download}"
}

ensure_git_remotes() {
  local url
  if git -C "$DEPLOY_ROOT" remote get-url "$GITHUB_REMOTE" >/dev/null 2>&1; then
    url=$(git -C "$DEPLOY_ROOT" remote get-url "$GITHUB_REMOTE")
    log "GitHub ($GITHUB_REMOTE): $url"
  else
    git -C "$DEPLOY_ROOT" remote add "$GITHUB_REMOTE" "$GITHUB_URL"
    log "added $GITHUB_REMOTE → $GITHUB_URL"
  fi

  if git -C "$DEPLOY_ROOT" remote get-url "$GITEE_REMOTE" >/dev/null 2>&1; then
    url=$(git -C "$DEPLOY_ROOT" remote get-url "$GITEE_REMOTE")
    log "Gitee ($GITEE_REMOTE): $url"
  else
    git -C "$DEPLOY_ROOT" remote add "$GITEE_REMOTE" "$GITEE_URL"
    log "added $GITEE_REMOTE → $GITEE_URL"
  fi
}

read_version() {
  [[ -f "$VERSION_FILE" ]] || die "missing $VERSION_FILE"
  tr -d ' \t\r\n' <"$VERSION_FILE"
}

validate_semver() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]] \
    || die "invalid semver: $v (expected X.Y.Z)"
}

sed_inplace() {
  local expr=$1
  local file=$2
  if [[ "$(uname -s)" == Darwin ]]; then
    sed -i '' "$expr" "$file"
  else
    sed -i "$expr" "$file"
  fi
}

sync_version() {
  local v="$1"
  validate_semver "$v"
  printf '%s\n' "$v" >"$VERSION_FILE"

  sed_inplace "s/^version = \".*\"/version = \"$v\"/" "$CARGO_TOML"

  if command -v node >/dev/null 2>&1; then
    node -e "
      const fs = require('fs');
      const p = process.argv[1];
      const v = process.argv[2];
      const j = JSON.parse(fs.readFileSync(p, 'utf8'));
      j.version = v;
      fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
    " "$MCP_PKG" "$v"
  else
    die "node required to sync packages/brokr-mcp/package.json"
  fi

  if [[ -f "$HOMEBREW_RB" ]]; then
    sed_inplace "s/^  version \".*\"/  version \"$v\"/" "$HOMEBREW_RB"
    sed_inplace "s|github.com/[^/]*/brokr/releases/download/v[0-9.]*|github.com/Furowu/brokr/releases/download/v${v}|g" "$HOMEBREW_RB"
  fi

  log "version synced → $v (VERSION, Cargo.toml, brokr-mcp, homebrew)"
}

assert_clean_git() {
  if git -C "$DEPLOY_ROOT" diff --quiet && git -C "$DEPLOY_ROOT" diff --cached --quiet; then
    return 0
  fi
  if [[ "${DEPLOY_ALLOW_DIRTY:-}" == "1" ]]; then
    log "WARN: working tree dirty (DEPLOY_ALLOW_DIRTY=1)"
    return 0
  fi
  die "working tree dirty — commit or stash first, or DEPLOY_ALLOW_DIRTY=1"
}

scan_sensitive_in_dir() {
  local dir="$1"
  local found=0
  local name
  for name in "${SENSITIVE_NAMES[@]}"; do
    if [[ -e "$dir/$name" ]]; then
      log "SENSITIVE: $dir/$name"
      found=1
    fi
  done
  if find "$dir" \( -name '.env*' -o -name '.master_kek' -o -name '.audit_hmac' \) -print -quit 2>/dev/null | grep -q .; then
    log "SENSITIVE: env/key files under $dir"
    found=1
  fi
  return "$found"
}

verify_mcp_package_clean() {
  local tmp tgz entry base n
  tmp=$(mktemp -d)
  (cd "$MCP_DIR" && npm pack --silent --pack-destination "$tmp")
  tgz=$(find "$tmp" -name '*.tgz' | head -1)
  [[ -n "$tgz" ]] || die "npm pack produced no tarball"
  while IFS= read -r entry; do
    base=$(basename "$entry")
    for n in "${SENSITIVE_NAMES[@]}"; do
      [[ "$base" == "$n" ]] && die "sensitive file in npm pack: $entry"
    done
    [[ "$entry" == *".env"* ]] && die "sensitive file in npm pack: $entry"
  done < <(tar -tzf "$tgz")
  rm -rf "$tmp"
  log "npm pack scrub OK ($(basename "$tgz"))"
}

target_binary_path() {
  local target="$1"
  if [[ "$target" == *windows* ]]; then
    printf '%s/target/%s/release/brokr.exe' "$DEPLOY_ROOT" "$target"
  else
    printf '%s/target/%s/release/brokr' "$DEPLOY_ROOT" "$target"
  fi
}

build_release_native() {
  local v bin
  v=$(read_version)
  log "building brokr v$v (native host only)..."
  (cd "$DEPLOY_ROOT" && cargo build --release)
  bin="$DEPLOY_ROOT/target/release/brokr"
  [[ -f "$bin" ]] || die "missing $bin"
  if command -v strip >/dev/null 2>&1; then
    strip "$bin" 2>/dev/null || true
  fi
  if [[ "$(uname -s)" == Darwin ]] && command -v codesign >/dev/null 2>&1; then
    codesign -s - -f "$bin" 2>/dev/null || true
  fi
  "$bin" --version >/dev/null || log "WARN: brokr --version failed"
  log "binary: $bin"
}

build_release() {
  build_release_native
}

pack_one_target() {
  local target="$1"
  local staging="$DIST_DIR/.staging-${target}"
  local out="$DIST_DIR/brokr-${target}.tar.gz"
  rm -rf "$staging"
  mkdir -p "$staging"
  if [[ "$target" == *windows* ]]; then
    cp "$(target_binary_path "$target")" "$staging/brokr.exe"
    scan_sensitive_in_dir "$staging" || die "sensitive files in dist staging"
    tar -czf "$out" -C "$staging" brokr.exe
  else
    cp "$(target_binary_path "$target")" "$staging/brokr"
    chmod 755 "$staging/brokr"
    scan_sensitive_in_dir "$staging" || die "sensitive files in dist staging"
    tar -czf "$out" -C "$staging" brokr
  fi
  rm -rf "$staging"
  log "dist: $out"
}

pack_dist_all() {
  local v target packed=0
  v=$(read_version)
  mkdir -p "$DIST_DIR"
  rm -f "$DIST_DIR"/brokr-*.tar.gz "$DIST_DIR"/checksums.txt
  for target in "${RELEASE_TARGETS[@]}"; do
    if [[ -f "$(target_binary_path "$target")" ]]; then
      pack_one_target "$target"
      packed=$((packed + 1))
    else
      log "skip $target (no local binary — release assets come from GitHub Actions)"
    fi
  done
  ((${packed} > 0)) || die "no binaries to pack — run ./d build for this host, or download CI artifacts into target/"
  (
    cd "$DIST_DIR"
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum brokr-*.tar.gz >checksums.txt
    else
      shasum -a 256 brokr-*.tar.gz >checksums.txt
    fi
  )
  verify_mcp_package_clean
  (cd "$MCP_DIR" && npm pack --pack-destination "$DIST_DIR")
  log "dist: $packed tarball(s) + checksums.txt in $DIST_DIR/ (full release: GitHub Actions)"
}

pack_dist() {
  pack_dist_all
}

verify_release_assets() {
  local v target url
  v=$(read_version)
  for target in "${RELEASE_TARGETS[@]}"; do
    url="${HOMEBREW_RELEASE_BASE}/v${v}/brokr-${target}.tar.gz"
    curl -fsSL -o /dev/null "$url" \
      || die "release asset missing: $url"
  done
  log "all ${#RELEASE_TARGETS[@]} GitHub release assets verified for v${v}"
}

publish_npm() {
  local v
  v=$(read_version)
  log "checking GitHub release assets before npm publish..."
  verify_release_assets
  verify_mcp_package_clean
  log "publishing @techinone/brokr@$v to npm..."
  (cd "$MCP_DIR" && npm publish --access public)
  log "npm publish done"
}

publish_github() {
  local v remote tag
  ensure_git_remotes
  v=$(read_version)
  remote="$GITHUB_REMOTE"
  tag="v${v}"
  assert_clean_git
  sync_git_with_remote "$remote"
  if git -C "$DEPLOY_ROOT" ls-remote --exit-code --tags "$remote" "refs/tags/${tag}" >/dev/null 2>&1; then
    die "tag $tag already exists on $remote"
  fi
  if ! git -C "$DEPLOY_ROOT" rev-parse "$tag" >/dev/null 2>&1; then
    log "git tag $tag"
    git -C "$DEPLOY_ROOT" tag -a "$tag" -m "release $tag"
  else
    log "tag $tag exists locally — pushing to $remote"
  fi
  log "push $remote (GitHub Actions builds all platforms)"
  git -C "$DEPLOY_ROOT" push "$remote" HEAD
  git -C "$DEPLOY_ROOT" push "$remote" "$tag"
  wait_for_github_release "$v"
  verify_release_assets
  log "GitHub: release $tag ready (CI assets verified)"
}

publish_gitee() {
  local v remote tag branch
  ensure_git_remotes
  v=$(read_version)
  remote="$GITEE_REMOTE"
  branch="$GITEE_BRANCH"
  tag="v${v}"
  git -C "$DEPLOY_ROOT" remote get-url "$remote" >/dev/null 2>&1 \
    || die "git remote '$remote' not found — run ./d remotes"
  log "push $remote $branch + tag $tag"
  git -C "$DEPLOY_ROOT" push "$remote" "$branch"
  if git -C "$DEPLOY_ROOT" rev-parse "$tag" >/dev/null 2>&1; then
    git -C "$DEPLOY_ROOT" push "$remote" "$tag"
  else
    git -C "$DEPLOY_ROOT" tag -a "$tag" -m "release $tag"
    git -C "$DEPLOY_ROOT" push "$remote" "$tag"
  fi
  log "Gitee: pushed to $remote"
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    sha256sum "$1" | awk '{print $1}'
  fi
}

artifact_sha256() {
  local v="$1"
  local target="$2"
  local from_dist="${3:-0}"
  local local_release="$DIST_DIR/brokr-${target}.tar.gz"
  local local_versioned="$DIST_DIR/brokr-${target}-v${v}.tar.gz"
  local tmp url

  if [[ "$from_dist" == "1" ]]; then
    if [[ -f "$local_release" ]]; then
      sha256_file "$local_release"
      return 0
    fi
    if [[ -f "$local_versioned" ]]; then
      sha256_file "$local_versioned"
      return 0
    fi
    die "missing dist artifact for $target (run ./d pack first)"
  fi

  tmp=$(mktemp)
  url="${HOMEBREW_RELEASE_BASE}/v${v}/brokr-${target}.tar.gz"
  if curl -fsSL "$url" -o "$tmp"; then
    sha256_file "$tmp"
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"

  if [[ -f "$local_release" ]]; then
    log "WARN: GitHub asset missing for $target — using dist/brokr-${target}.tar.gz"
    sha256_file "$local_release"
    return 0
  fi
  if [[ -f "$local_versioned" ]]; then
    log "WARN: GitHub asset missing for $target — using dist/brokr-${target}-v${v}.tar.gz"
    sha256_file "$local_versioned"
    return 0
  fi
  die "cannot fetch brokr-${target}.tar.gz for v${v} (wait for GitHub Release CI or use ./d brew --from-dist)"
}

wait_for_github_release() {
  local v="$1"
  local attempt url
  log "waiting for GitHub release v${v} assets (up to 15 min)..."
  for attempt in $(seq 1 30); do
    url="${HOMEBREW_RELEASE_BASE}/v${v}/brokr-x86_64-apple-darwin.tar.gz"
    if curl -fsSL -o /dev/null -w '' "$url" 2>/dev/null; then
      log "release assets ready (attempt $attempt)"
      return 0
    fi
    sleep 30
  done
  die "GitHub release v${v} assets not ready — check Actions or use ./d brew --from-dist"
}

write_homebrew_formula() {
  local v="$1"
  local sha_intel="$2"
  local sha_arm="$3"
  local sha_linux_intel="$4"
  local sha_linux_arm="$5"
  cat >"$HOMEBREW_RB" <<EOF
class Brokr < Formula
  desc "AI-safe credential broker CLI"
  homepage "https://github.com/Furowu/brokr"
  version "$v"

  if OS.mac? && Hardware::CPU.intel?
    url "${HOMEBREW_RELEASE_BASE}/v${v}/brokr-x86_64-apple-darwin.tar.gz"
    sha256 "$sha_intel"
  elsif OS.mac? && Hardware::CPU.arm?
    url "${HOMEBREW_RELEASE_BASE}/v${v}/brokr-aarch64-apple-darwin.tar.gz"
    sha256 "$sha_arm"
  elsif OS.linux? && Hardware::CPU.intel?
    url "${HOMEBREW_RELEASE_BASE}/v${v}/brokr-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "$sha_linux_intel"
  elsif OS.linux? && Hardware::CPU.arm?
    url "${HOMEBREW_RELEASE_BASE}/v${v}/brokr-aarch64-unknown-linux-gnu.tar.gz"
    sha256 "$sha_linux_arm"
  end

  def install
    bin.install "brokr"
  end

  test do
    system "#{bin}/brokr", "--version"
  end
end
EOF
  log "wrote $HOMEBREW_RB with release sha256 checksums"
}

update_homebrew_formula() {
  local v from_dist wait_release
  from_dist=0
  wait_release=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --from-dist) from_dist=1 ;;
      --wait) wait_release=1 ;;
      *) die "unknown brew flag: $1" ;;
    esac
    shift
  done
  v=$(read_version)
  if [[ "$from_dist" == "0" && "$wait_release" == "1" ]]; then
    wait_for_github_release "$v"
  fi
  local sha_intel sha_arm sha_linux_intel sha_linux_arm
  sha_intel=$(artifact_sha256 "$v" x86_64-apple-darwin "$from_dist")
  sha_arm=$(artifact_sha256 "$v" aarch64-apple-darwin "$from_dist")
  sha_linux_intel=$(artifact_sha256 "$v" x86_64-unknown-linux-gnu "$from_dist")
  sha_linux_arm=$(artifact_sha256 "$v" aarch64-unknown-linux-gnu "$from_dist")
  write_homebrew_formula "$v" "$sha_intel" "$sha_arm" "$sha_linux_intel" "$sha_linux_arm"
}

publish_homebrew_tap() {
  local v tap_dir formula_dest
  v=$(read_version)
  [[ -f "$HOMEBREW_RB" ]] || die "missing $HOMEBREW_RB — run ./d brew first"
  if grep -q 'PLACEHOLDER' "$HOMEBREW_RB" 2>/dev/null; then
    die "homebrew formula still has PLACEHOLDER sha256 — run ./d brew"
  fi

  tap_dir="$HOMEBREW_TAP_DIR"
  if [[ ! -d "$tap_dir/.git" ]]; then
    log "cloning homebrew tap → $tap_dir"
    git clone "$HOMEBREW_TAP_REMOTE" "$tap_dir"
  fi
  git -C "$tap_dir" pull --rebase origin main 2>/dev/null \
    || git -C "$tap_dir" pull --rebase origin master 2>/dev/null \
    || true

  formula_dest="$tap_dir/Formula/brokr.rb"
  mkdir -p "$(dirname "$formula_dest")"
  cp "$HOMEBREW_RB" "$formula_dest"

  if git -C "$tap_dir" diff --quiet && git -C "$tap_dir" diff --cached --quiet; then
    log "homebrew tap unchanged (already v$v?)"
    return 0
  fi
  git -C "$tap_dir" add Formula/brokr.rb
  git -C "$tap_dir" commit -m "brokr $v"
  git -C "$tap_dir" push
  log "homebrew tap published: $HOMEBREW_TAP_REMOTE (Formula/brokr.rb @ v$v)"
  log "install: brew tap Furowu/brokr && brew install brokr"
}

publish_brew() {
  update_homebrew_formula "$@"
  publish_homebrew_tap
}

commit_version_bump() {
  local v msg
  v=$(read_version)
  msg="${1:-chore: release v${v}}"
  git -C "$DEPLOY_ROOT" add VERSION Cargo.toml packages/brokr-mcp/package.json homebrew/brokr.rb
  if git -C "$DEPLOY_ROOT" diff --cached --quiet; then
    log "version already at v$v (nothing to commit)"
    return 0
  fi
  git -C "$DEPLOY_ROOT" commit -m "$msg"
  log "committed version bump v$v"
}

# Rebase current branch onto remote before push (avoids non-fast-forward on release).
sync_git_with_remote() {
  local remote="$1"
  local branch
  branch=$(git -C "$DEPLOY_ROOT" rev-parse --abbrev-ref HEAD)
  git -C "$DEPLOY_ROOT" fetch "$remote"
  if ! git -C "$DEPLOY_ROOT" show-ref --verify --quiet "refs/remotes/${remote}/${branch}"; then
    log "no ${remote}/${branch} — skip rebase"
    return 0
  fi
  local behind
  behind=$(git -C "$DEPLOY_ROOT" rev-list --count "HEAD..${remote}/${branch}")
  if [[ "$behind" -eq 0 ]]; then
    return 0
  fi
  log "rebasing onto ${remote}/${branch} ($behind commit(s) behind)..."
  git -C "$DEPLOY_ROOT" pull --rebase "$remote" "$branch" \
    || die "git rebase failed — resolve conflicts, then retry"
}
