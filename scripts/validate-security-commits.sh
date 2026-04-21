#!/bin/bash
# Security commit message validation script
# Validates that commits claiming security fixes actually modify security-relevant files

set -euo pipefail

# Define security-relevant paths
SECURITY_PATHS=(
    "crates/franken-node/src/api/middleware.rs"     # Auth, authz, rate limiting
    "crates/franken-node/src/security/"             # Security modules
    "crates/franken-node/src/supply_chain/"         # Supply chain security
    "crates/franken-node/Cargo.toml"                # Feature flags that affect security
    "crates/franken-node/src/storage/"              # Data access security
    "crates/franken-node/src/runtime/"              # Runtime security
)

# Check if commit message claims security fix
is_security_commit() {
    local commit_msg="$1"
    echo "$commit_msg" | grep -qi -E "(security|SECURITY|fix.*security|Security.*fix|auth.*fix|rate.*limit.*fix)"
}

# Check if any security-relevant files were modified
has_security_changes() {
    local commit_hash="$1"
    local changed_files
    changed_files=$(git show --name-only --format= "$commit_hash")

    for security_path in "${SECURITY_PATHS[@]}"; do
        if echo "$changed_files" | grep -q "$security_path"; then
            return 0
        fi
    done
    return 1
}

# Validate a single commit
validate_commit() {
    local commit_hash="$1"
    local commit_msg
    commit_msg=$(git log --format=%B -n 1 "$commit_hash")

    if is_security_commit "$commit_msg"; then
        echo "🔍 Security commit detected: $commit_hash"
        echo "   Message: $(echo "$commit_msg" | head -n1)"

        # Check if it actually contains security changes
        if has_security_changes "$commit_hash"; then
            echo "   ✅ VALID: Modifies security-relevant files"
            return 0
        else
            echo "   ❌ INVALID: Claims security fix but no security files modified"
            echo "   Changed files:"
            git show --name-only --format= "$commit_hash" | sed 's/^/      /'
            return 1
        fi
    fi
}

# Main function
main() {
    local commit_range="${1:-HEAD~20..HEAD}"
    echo "🔍 Auditing commits in range: $commit_range"
    echo

    local invalid_count=0
    local security_count=0

    # Get all commits in reverse chronological order
    while IFS= read -r commit_hash; do
        local commit_msg
        commit_msg=$(git log --format=%B -n 1 "$commit_hash")

        if is_security_commit "$commit_msg"; then
            ((security_count++))
            if ! validate_commit "$commit_hash"; then
                ((invalid_count++))
            fi
            echo
        fi
    done < <(git rev-list "$commit_range")

    echo "📊 Audit Results:"
    echo "   Security commits found: $security_count"
    echo "   Invalid claims: $invalid_count"

    if [ "$invalid_count" -gt 0 ]; then
        echo "   ❌ Found $invalid_count commits with false security claims"
        exit 1
    else
        echo "   ✅ All security commits appear valid"
        exit 0
    fi
}

main "$@"