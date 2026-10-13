#!/usr/bin/env bash
# Materialize Cargo's sibling path dependencies without modifying existing work.
# Compatible with macOS Bash 3.2; no Python, sudo, /dp links or Cargo patches.
# A receipt records Git inputs, not successful compilation or certification.
set -euo pipefail
umask 077

fail() { printf 'source bootstrap: %s\n' "$*" >&2; exit 1; }
usage() {
  printf '%s\n' 'Usage: bootstrap_source.sh --workspace DIR --engine-ref REF --receipt FILE [--verify-only]'
}
valid_sha() {
  [ "${#1}" -eq 40 ] || return 1
  case "$1" in *[!0-9a-f]*) return 1 ;; esac
}
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else fail 'SHA-256 support is required (sha256sum or shasum)'; fi
}

WORKSPACE="" ENGINE_REF="" RECEIPT="" VERIFY_ONLY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --workspace|--engine-ref|--receipt)
      option="$1"; shift
      [ "$#" -gt 0 ] && [ -n "$1" ] || fail "$option requires a value"
      case "$option" in
        --workspace) WORKSPACE="$1" ;;
        --engine-ref) ENGINE_REF="$1" ;;
        --receipt) RECEIPT="$1" ;;
      esac ;;
    --verify-only) VERIFY_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
  shift
done
[ -n "$WORKSPACE" ] && [ -n "$ENGINE_REF" ] && [ -n "$RECEIPT" ] || { usage >&2; exit 1; }
command -v git >/dev/null 2>&1 || fail 'git is required'
# check-ref-format rejects option injection, refspec destinations and controls.
git check-ref-format --branch "$ENGINE_REF" >/dev/null 2>&1 || fail 'invalid engine ref'
if [ "$VERIFY_ONLY" -eq 1 ]; then
  valid_sha "$ENGINE_REF" || fail '--verify-only requires the resolved engine commit'
fi
[ -d "$WORKSPACE" ] && [ ! -L "$WORKSPACE" ] || fail 'workspace must be an ordinary directory'
WORKSPACE="$(cd "$WORKSPACE" && pwd -P)" || fail 'cannot resolve workspace'
PARENT="$(dirname "$WORKSPACE")"
[ -f "$WORKSPACE/Cargo.toml" ] && [ ! -L "$WORKSPACE/Cargo.toml" ] || fail 'workspace Cargo.toml is missing or linked'
LOCK="$WORKSPACE/packaging/source-siblings.tsv"
[ -f "$LOCK" ] && [ ! -L "$LOCK" ] || fail 'workspace lacks a regular packaging/source-siblings.tsv'
size="$(wc -c < "$LOCK")" || fail 'cannot inspect source lock'
[ "$size" -le 4096 ] || fail 'source lock exceeds 4096 bytes'
LOCK_SHA="$(sha256_file "$LOCK")" || fail 'cannot hash source lock'

REPOS=(franken_engine)
REFS=("$ENGINE_REF")
SEEN=' '
# Admit the ENTIRE lock before any checkout or network operation. Never source
# it as shell code, accept repository URLs, or silently fall back to main.
while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|\#*) continue ;; esac
  IFS=$'\t' read -r repo revision extra <<< "$line"
  [ "$line" = "$repo"$'\t'"$revision" ] && [ -z "${extra:-}" ] || fail 'source lock requires exactly two tab-separated fields'
  case "$repo" in frankentui|fastapi_rust|sqlmodel_rust) ;; *) fail "unexpected sibling: $repo" ;; esac
  valid_sha "$revision" || fail "sibling $repo requires an immutable lowercase commit SHA"
  case "$SEEN" in *" $repo "*) fail "duplicate sibling: $repo" ;; esac
  SEEN="$SEEN$repo "
  REPOS+=("$repo")
  REFS+=("$revision")
done < "$LOCK"
for repo in frankentui fastapi_rust sqlmodel_rust; do
  case "$SEEN" in *" $repo "*) ;; *) fail "source lock omits $repo" ;; esac
done
[ "${#REPOS[@]}" -eq 4 ] || fail 'incomplete sibling inventory'

# Existing outputs and source trees are never overwritten. Canonical parents
# also prevent a receipt alias from dirtying an input repository.
[ ! -e "$RECEIPT" ] && [ ! -L "$RECEIPT" ] || fail 'receipt already exists'
receipt_parent="$(cd "$(dirname "$RECEIPT")" && pwd -P)" || fail 'receipt parent must exist'
RECEIPT="$receipt_parent/$(basename "$RECEIPT")"
case "$receipt_parent/" in "$WORKSPACE/"*) fail 'receipt must be outside the workspace' ;; esac
for repo in ${REPOS[@]+"${REPOS[@]}"}; do
  case "$receipt_parent/" in "$PARENT/$repo/"*) fail 'receipt must be outside sibling repositories' ;; esac
done

check_repo() {
  local directory="$1" expected="$2" top head dirty
  [ -d "$directory" ] && [ ! -L "$directory" ] \
    && [ -d "$directory/.git" ] && [ ! -L "$directory/.git" ] \
    || fail "not an ordinary standalone checkout: $directory"
  top="$(git -C "$directory" rev-parse --show-toplevel)" || fail "not a Git checkout: $directory"
  # Git for Windows may print a drive path; cd/pwd gives the same spelling
  # as Git Bash uses for WORKSPACE and PARENT.
  top="$(cd "$top" && pwd -P)" || fail 'cannot resolve Git worktree'
  [ "$top" = "$directory" ] || fail "nested or redirected checkout: $directory"
  head="$(git -C "$directory" rev-parse --verify 'HEAD^{commit}')" || fail 'checkout has no commit'
  valid_sha "$head" || fail 'unsupported Git object format'
  [ -z "$expected" ] || [ "$head" = "$expected" ] || fail "checkout revision mismatch: $directory"
  dirty="$(git -C "$directory" status --porcelain --untracked-files=all)" || fail 'cannot inspect checkout changes'
  [ -z "$dirty" ] || fail "checkout has local changes; refusing to modify it: $directory"
  printf '%s\n' "$head"
}
check_manifests() {
  local repo="$1" directory="$2" path paths parent
  case "$repo" in
    franken_engine) paths='crates/franken-engine/Cargo.toml crates/franken-extension-host/Cargo.toml' ;;
    frankentui) paths='crates/ftui/Cargo.toml' ;;
    fastapi_rust) paths='crates/fastapi/Cargo.toml' ;;
    sqlmodel_rust) paths='crates/sqlmodel/Cargo.toml crates/sqlmodel-core/Cargo.toml crates/sqlmodel-schema/Cargo.toml' ;;
  esac
  for path in Cargo.toml $paths; do
    parent="$(dirname "$directory/$path")"
    while [ "$parent" != "$directory" ]; do
      [ -d "$parent" ] && [ ! -L "$parent" ] || fail "$repo has a linked or missing Cargo manifest parent"
      parent="$(dirname "$parent")"
    done
    [ -f "$directory/$path" ] && [ ! -L "$directory/$path" ] \
      || fail "$repo does not provide required Cargo manifest: $path"
  done
}
NODE_SHA="$(check_repo "$WORKSPACE" '')" || fail 'workspace is not a clean committed source'

# Check existing siblings up front. Never reset, clean, fetch into, repair or
# remove a pre-existing checkout, even when a later dependency is missing.
for ((i=0; i<${#REPOS[@]}; i++)); do
  destination="$PARENT/${REPOS[$i]}"
  if [ -e "$destination" ] || [ -L "$destination" ]; then
    valid_sha "${REFS[$i]}" || fail 'an existing engine checkout requires an exact commit, not a moving ref'
    check_repo "$destination" "${REFS[$i]}" >/dev/null || fail 'existing sibling cannot be reused'
    check_manifests "${REPOS[$i]}" "$destination"
  elif [ "$VERIFY_ONLY" -eq 1 ]; then
    fail "missing sibling in verify-only mode: ${REPOS[$i]}"
  fi
done

ACTUAL=()
for ((i=0; i<${#REPOS[@]}; i++)); do
  repo="${REPOS[$i]}" ref="${REFS[$i]}" destination="$PARENT/${REPOS[$i]}"
  if [ ! -e "$destination" ] && [ ! -L "$destination" ]; then
    # mkdir reserves this exact name without clobbering a concurrent checkout.
    # Failed/interrupted new checkouts remain for diagnosis. They cannot be
    # mistaken for complete inputs on a retry; no existing work is removed.
    mkdir "$destination" || fail "cannot reserve sibling directory: $repo"
    git -C "$destination" -c init.templateDir= init --quiet || fail "cannot initialize $repo"
    git -C "$destination" remote add origin "https://github.com/Dicklesworthstone/$repo.git" \
      || fail "cannot configure $repo origin"
    git -C "$destination" fetch --no-tags --depth 1 origin "$ref" || fail "cannot fetch requested $repo revision"
    resolved="$(git -C "$destination" rev-parse --verify 'FETCH_HEAD^{commit}')" || fail "invalid $repo commit"
    valid_sha "$resolved" || fail 'unsupported Git object format'
    if valid_sha "$ref"; then
      [ "$resolved" = "$ref" ] || fail "fetched $repo commit differs from its pin"
    fi
    git -C "$destination" -c core.autocrlf=false -c core.hooksPath=/dev/null \
      checkout --quiet --detach "$resolved" || fail "cannot check out $repo"
  else
    resolved="${REFS[$i]}"
  fi
  ACTUAL+=("$(check_repo "$destination" "$resolved")")
  [ "${ACTUAL[$i]}" = "$resolved" ] || fail "cannot verify $repo"
  check_manifests "$repo" "$destination"
done
# Bind the same source lock and revisions throughout the operation, not just at
# the beginning. Git provenance is not a whole-environment or hostile-OS claim.
[ "$(sha256_file "$LOCK")" = "$LOCK_SHA" ] || fail 'source lock changed during bootstrap'
check_repo "$WORKSPACE" "$NODE_SHA" >/dev/null || fail 'workspace changed during bootstrap'
for ((i=0; i<${#REPOS[@]}; i++)); do
  check_repo "$PARENT/${REPOS[$i]}" "${ACTUAL[$i]}" >/dev/null || fail 'sibling changed during bootstrap'
done
(
  set -o noclobber
  {
    printf '# franken-node/source-inputs/v1\n'
    printf '# source-siblings-sha256\t%s\n' "$LOCK_SHA"
    printf 'franken_node\t%s\n' "$NODE_SHA"
    for ((i=0; i<${#REPOS[@]}; i++)); do
      printf '%s\t%s\n' "${REPOS[$i]}" "${ACTUAL[$i]}"
    done
  } > "$RECEIPT"
) || fail 'cannot publish new source receipt'
printf 'Source inputs verified; receipt: %s\n' "$RECEIPT" >&2
