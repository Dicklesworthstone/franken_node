#!/usr/bin/env bash
set -euo pipefail

REPO_OWNER="Dicklesworthstone"
NODE_REPO="franken_node"
ENGINE_REPO="franken_engine"
BINARY_NAME="franken-node"
DEFAULT_PREFIX="${HOME}/.local"
DEFAULT_METHOD="auto"

PREFIX="${DEFAULT_PREFIX}"
METHOD="${DEFAULT_METHOD}"
NODE_REF="${FRANKEN_NODE_REF:-main}"
ENGINE_REF="${FRANKEN_ENGINE_REF:-main}"
WORK_DIR=""

usage() {
    cat <<'EOF'
Install franken-node.

Usage:
  install.sh [--prefix PATH] [--method auto|release|source]
             [--node-ref REF] [--engine-ref REF]
  install.sh --help

Options:
  --prefix PATH       Install under PATH/bin (default: ~/.local/bin).
  --method MODE       auto tries a checksum-verified GitHub release first, then
                      falls back to a source bootstrap when no release exists.
                      Valid values: auto, release, source.
  --node-ref REF      Git ref for the franken_node source bootstrap path.
                      Default: main.
  --engine-ref REF    Git ref for the franken_engine source bootstrap path.
                      Default: main.
  -h, --help          Show this help text.

Notes:
  - Current repository reality: if no published GitHub release exists yet, the
    installer falls back to cloning franken_node + franken_engine side-by-side
    and building franken-node from source.
  - Release installs verify the downloaded archive against SHA256SUMS before
    extraction.
EOF
}

log() {
    printf '[franken-node-install] %s\n' "$*"
}

warn() {
    printf '[franken-node-install] warning: %s\n' "$*" >&2
}

die() {
    warn "$*"
    exit 1
}

cleanup() {
    if [ -n "${WORK_DIR:-}" ] && [ -d "${WORK_DIR}" ]; then
        case "${WORK_DIR}" in
            "${TMPDIR:-/tmp}"/franken-node-install.*)
                rm -rf -- "${WORK_DIR}"
                ;;
            *)
                warn "refusing to remove unexpected temporary directory: ${WORK_DIR}"
                ;;
        esac
    fi
}

trap cleanup EXIT INT TERM

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_command() {
    if ! command_exists "$1"; then
        die "required command not found: $1"
    fi
}

compute_sha256() {
    local file="$1"

    if command_exists sha256sum; then
        sha256sum "${file}" | awk '{print $1}'
        return 0
    fi

    if command_exists shasum; then
        shasum -a 256 "${file}" | awk '{print $1}'
        return 0
    fi

    if command_exists openssl; then
        openssl dgst -sha256 "${file}" | awk '{print $NF}'
        return 0
    fi

    die "no SHA-256 tool found; install sha256sum, shasum, or openssl"
}

normalize_os() {
    case "$1" in
        Linux)
            printf '%s\n' "linux"
            ;;
        Darwin)
            printf '%s\n' "darwin"
            ;;
        *)
            return 1
            ;;
    esac
}

normalize_arch() {
    case "$1" in
        x86_64|amd64)
            printf '%s\n' "amd64"
            ;;
        aarch64|arm64|arm64e)
            printf '%s\n' "arm64"
            ;;
        *)
            return 1
            ;;
    esac
}

detect_os() {
    local uname_s

    uname_s="${FRANKEN_NODE_UNAME_S:-$(uname -s)}"
    normalize_os "${uname_s}" || die "unsupported operating system: ${uname_s}"
}

detect_arch() {
    local uname_m

    uname_m="${FRANKEN_NODE_UNAME_M:-$(uname -m)}"
    normalize_arch "${uname_m}" || die "unsupported architecture: ${uname_m}"
}

release_asset_name() {
    local tag="$1"
    local os="$2"
    local arch="$3"

    printf '%s-%s-%s_%s.tar.gz\n' "${BINARY_NAME}" "${tag}" "${os}" "${arch}"
}

latest_release_api_url() {
    printf 'https://api.github.com/repos/%s/%s/releases/latest\n' \
        "${REPO_OWNER}" "${NODE_REPO}"
}

release_download_url() {
    local tag="$1"
    local file_name="$2"

    printf 'https://github.com/%s/%s/releases/download/%s/%s\n' \
        "${REPO_OWNER}" "${NODE_REPO}" "${tag}" "${file_name}"
}

discover_latest_release_tag() {
    local response tag

    if ! response="$(curl -fsSL "$(latest_release_api_url)" 2>/dev/null)"; then
        return 1
    fi

    tag="$(
        printf '%s\n' "${response}" \
            | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
            | head -n 1
    )"

    [ -n "${tag}" ] || return 1
    printf '%s\n' "${tag}"
}

download_file() {
    local url="$1"
    local destination="$2"

    curl -fL --retry 3 --retry-delay 1 --connect-timeout 15 \
        2>/dev/null \
        -o "${destination}" "${url}"
}

extract_manifest_sha() {
    local asset_name="$1"
    local manifest_path="$2"

    awk -v asset_name="${asset_name}" '
        NF >= 3 && $2 == asset_name {
            print $1
            exit
        }
    ' "${manifest_path}"
}

extract_manifest_size() {
    local asset_name="$1"
    local manifest_path="$2"

    awk -v asset_name="${asset_name}" '
        NF >= 3 && $2 == asset_name {
            print $3
            exit
        }
    ' "${manifest_path}"
}

install_binary() {
    local source_path="$1"
    local destination_dir="${PREFIX}/bin"
    local destination_path="${destination_dir}/${BINARY_NAME}"

    require_command install
    mkdir -p "${destination_dir}"
    install -m 0755 "${source_path}" "${destination_path}"
    printf '%s\n' "${destination_path}"
}

clone_ref() {
    local repo_name="$1"
    local destination="$2"
    local ref="$3"
    local repo_url="https://github.com/${REPO_OWNER}/${repo_name}.git"

    if git clone --filter=blob:none --depth 1 --branch "${ref}" "${repo_url}" "${destination}"; then
        return 0
    fi

    rm -rf -- "${destination}"
    mkdir -p "${destination}"

    (
        cd "${destination}"
        git init
        git remote add origin "${repo_url}"
        git fetch --depth 1 origin "${ref}"
        git checkout --detach FETCH_HEAD
    )
}

install_from_release() {
    local tag="$1"
    local os="$2"
    local arch="$3"
    local asset_name manifest_path archive_path extract_dir expected_sha expected_size actual_sha actual_size
    local extracted_binary installed_binary

    require_command tar

    asset_name="$(release_asset_name "${tag}" "${os}" "${arch}")"
    manifest_path="${WORK_DIR}/SHA256SUMS"
    archive_path="${WORK_DIR}/${asset_name}"
    extract_dir="${WORK_DIR}/release-extract"

    log "Attempting checksum-verified release install for ${asset_name}"

    if ! download_file "$(release_download_url "${tag}" "SHA256SUMS")" "${manifest_path}"; then
        warn "failed to download SHA256SUMS for release ${tag}"
        return 1
    fi

    expected_sha="$(extract_manifest_sha "${asset_name}" "${manifest_path}")"
    expected_size="$(extract_manifest_size "${asset_name}" "${manifest_path}")"
    if [ -z "${expected_sha}" ] || [ -z "${expected_size}" ]; then
        warn "release ${tag} does not publish a SHA256SUMS entry for ${asset_name}"
        return 1
    fi

    if ! download_file "$(release_download_url "${tag}" "${asset_name}")" "${archive_path}"; then
        warn "failed to download release asset ${asset_name}"
        return 1
    fi

    actual_sha="$(compute_sha256 "${archive_path}")"
    actual_size="$(wc -c < "${archive_path}" | tr -d '[:space:]')"
    if [ "${actual_sha}" != "${expected_sha}" ]; then
        die "SHA-256 mismatch for ${asset_name}: expected ${expected_sha}, got ${actual_sha}"
    fi
    if [ "${actual_size}" != "${expected_size}" ]; then
        die "size mismatch for ${asset_name}: expected ${expected_size}, got ${actual_size}"
    fi

    mkdir -p "${extract_dir}"
    tar -xzf "${archive_path}" -C "${extract_dir}"

    extracted_binary="$(
        find "${extract_dir}" -type f -name "${BINARY_NAME}" -perm -u+x | head -n 1
    )"
    if [ -z "${extracted_binary}" ]; then
        die "release archive ${asset_name} did not contain an executable ${BINARY_NAME}"
    fi

    installed_binary="$(install_binary "${extracted_binary}")"
    log "Installed ${BINARY_NAME} from release ${tag} to ${installed_binary}"
}

install_from_source() {
    local source_root node_dir engine_dir built_binary installed_binary

    require_command git
    if ! command_exists cargo; then
        die "cargo is required for source bootstrap; install Rust via rustup, or publish release artifacts first"
    fi

    source_root="${WORK_DIR}/source"
    node_dir="${source_root}/${NODE_REPO}"
    engine_dir="${source_root}/${ENGINE_REPO}"

    mkdir -p "${source_root}"

    log "Falling back to source bootstrap from ${NODE_REPO}@${NODE_REF} and ${ENGINE_REPO}@${ENGINE_REF}"
    clone_ref "${NODE_REPO}" "${node_dir}" "${NODE_REF}" \
        || die "failed to clone ${NODE_REPO} ref ${NODE_REF}"
    clone_ref "${ENGINE_REPO}" "${engine_dir}" "${ENGINE_REF}" \
        || die "failed to clone ${ENGINE_REPO} ref ${ENGINE_REF}"

    log "Building ${BINARY_NAME} from source"
    (
        cd "${node_dir}"
        cargo build --release -p frankenengine-node
    )

    built_binary="${node_dir}/target/release/${BINARY_NAME}"
    if [ ! -x "${built_binary}" ]; then
        die "expected built binary at ${built_binary}"
    fi

    installed_binary="$(install_binary "${built_binary}")"
    log "Installed ${BINARY_NAME} from source to ${installed_binary}"
}

print_post_install_summary() {
    local binary_path="${PREFIX}/bin/${BINARY_NAME}"
    local version_output=""

    if [ ! -x "${binary_path}" ]; then
        die "installed binary missing at ${binary_path}"
    fi

    if version_output="$("${binary_path}" --version 2>/dev/null)"; then
        printf '%s\n' "${version_output}"
    else
        warn "installed binary did not return a version string"
    fi

    case ":${PATH}:" in
        *":${PREFIX}/bin:"*)
            ;;
        *)
            warn "${PREFIX}/bin is not currently on PATH"
            ;;
    esac
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --prefix)
                shift
                [ $# -gt 0 ] || die "--prefix requires a path"
                PREFIX="$1"
                ;;
            --method)
                shift
                [ $# -gt 0 ] || die "--method requires auto, release, or source"
                METHOD="$1"
                ;;
            --node-ref)
                shift
                [ $# -gt 0 ] || die "--node-ref requires a git ref"
                NODE_REF="$1"
                ;;
            --engine-ref)
                shift
                [ $# -gt 0 ] || die "--engine-ref requires a git ref"
                ENGINE_REF="$1"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "unknown argument: $1"
                ;;
        esac
        shift
    done

    case "${METHOD}" in
        auto|release|source)
            ;;
        *)
            die "unsupported --method value: ${METHOD}"
            ;;
    esac
}

main() {
    local os arch release_tag=""

    parse_args "$@"
    require_command curl

    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/franken-node-install.XXXXXXXX")"

    os="$(detect_os)"
    arch="$(detect_arch)"

    log "Detected platform ${os}/${arch}"
    log "Using install prefix ${PREFIX}"

    if [ "${METHOD}" = "auto" ] || [ "${METHOD}" = "release" ]; then
        if release_tag="$(discover_latest_release_tag)"; then
            if install_from_release "${release_tag}" "${os}" "${arch}"; then
                print_post_install_summary
                return 0
            fi

            if [ "${METHOD}" = "release" ]; then
                die "release install failed for latest published tag ${release_tag}"
            fi

            warn "no usable release asset found for ${os}/${arch}; falling back to source bootstrap"
        else
            if [ "${METHOD}" = "release" ]; then
                die "no published GitHub releases found for ${REPO_OWNER}/${NODE_REPO}"
            fi

            warn "no published GitHub releases found; falling back to source bootstrap"
        fi
    fi

    install_from_source
    print_post_install_summary
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
