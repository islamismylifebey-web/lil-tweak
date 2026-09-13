#!/usr/bin/bash -p
set +x
set -euo pipefail
IFS=$'\n\t'
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
PYTHON=/usr/bin/python3
readonly PATH LC_ALL PYTHON
unset CDPATH ENV BASH_ENV PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONINSPECT \
  PYTHONWARNINGS PYTHONBREAKPOINT PYTHONUSERBASE PYTHONPYCACHEPREFIX
umask 077

TUNNEL_USER="lil-tweak-tunnel"
CONFIG_DIR="/etc/lil-tweak-cloudflared"
EXPECTED_HOST="galor-tweak-runner-01"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
TEMPLATE="${PROJECT_DIR}/deploy/cloudflared/config.yml.example"
UNIT="${PROJECT_DIR}/deploy/cloudflared/lil-tweak-cloudflared.service"
VALIDATOR="${PROJECT_DIR}/deploy/cloudflared/validate_credentials.py"
BINARY_VERIFIER_SOURCE="${PROJECT_DIR}/deploy/cloudflared/verify_binary.py"
BINARY_VERIFIER_TARGET="/usr/local/libexec/lil-tweak/cloudflared-verify-exec.py"
ROLLBACK_HELPER="${PROJECT_DIR}/scripts/lil-tweak-rollback.py"
HOST_IDENTITY_HELPER="${PROJECT_DIR}/scripts/lil-tweak-host-identity.py"
staging_file=""
unit_staging_file=""
credentials_snapshot=""
rollback_receipt=""
rollback_manifest_sha256=""
mutation_started=0
rollback_attempted=0
rollback_owned_by_wrapper=0

exec_without_rollback_lease() {
  local lease_fd="${LIL_TWEAK_ROLLBACK_LEASE_FD:-}"
  [[ $# -gt 0 && "${lease_fd}" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  exec {lease_fd}>&-
  unset LIL_TWEAK_ROLLBACK_LEASE_FD
  exec "$@"
}

cleanup_release_state() {
  local cleanup_status=0
  if [[ -n "${staging_file}" && "${staging_file}" == /tmp/lil-tweak-cloudflared.*.yml ]]; then
    rm -f -- "${staging_file}" || cleanup_status=1
    [[ ! -e "${staging_file}" && ! -L "${staging_file}" ]] || cleanup_status=1
  fi
  if [[ -n "${unit_staging_file}" \
      && "${unit_staging_file}" == /tmp/lil-tweak-cloudflared-unit.*.service ]]; then
    rm -f -- "${unit_staging_file}" || cleanup_status=1
    [[ ! -e "${unit_staging_file}" && ! -L "${unit_staging_file}" ]] \
      || cleanup_status=1
  fi
  if [[ -n "${credentials_snapshot}" \
      && "${credentials_snapshot}" == /tmp/lil-tweak-tunnel-credentials.*.json ]]; then
    rm -f -- "${credentials_snapshot}" || cleanup_status=1
    [[ ! -e "${credentials_snapshot}" && ! -L "${credentials_snapshot}" ]] \
      || cleanup_status=1
  fi
  return "${cleanup_status}"
}

finish_install() {
  local original_status=$? status cleanup_status=0
  status=${original_status}
  trap - EXIT HUP INT TERM
  cleanup_release_state || cleanup_status=1
  if [[ ${status} -eq 0 && ${cleanup_status} -ne 0 ]]; then
    status=1
  fi
  if [[ ${status} -ne 0 && ${mutation_started} -eq 1 \
      && ${rollback_attempted} -eq 0 && ${rollback_owned_by_wrapper} -eq 0 ]]; then
    rollback_attempted=1
    "${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" restore \
      --receipt "${rollback_receipt}" \
      --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null \
      || { [[ ${original_status} -ne 0 ]] && status=${original_status} || status=1; }
  fi
  exit "${status}"
}

trap finish_install EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
  printf 'install-cloudflare-tunnel: %s\n' "$*" >&2
  exit 1
}

offline_check() {
  for required in \
    "${TEMPLATE}" "${UNIT}" "${VALIDATOR}" "${BINARY_VERIFIER_SOURCE}" \
    "${ROLLBACK_HELPER}" \
    "${HOST_IDENTITY_HELPER}"
  do
    [[ -f "${required}" && ! -L "${required}" ]] || die "missing deployment input: ${required}"
  done
  grep -Fq 'service: http://127.0.0.1:8017' "${TEMPLATE}" \
    || die 'Tunnel origin must be loopback-only port 8017'
  grep -Fq 'service: http_status:404' "${TEMPLATE}" \
    || die 'Tunnel catch-all deny rule is missing'
  [[ "$(grep -Foc '@@LIL_TWEAK_CLOUDFLARED_SHA256@@' "${UNIT}")" -eq 2 ]] \
    || die 'cloudflared unit must bind the audited digest at both executions'
  [[ -x "${ROLLBACK_HELPER}" ]] || die 'rollback helper must be executable'
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" --check >/dev/null \
    || die 'rollback helper check failed'
  [[ -x "${HOST_IDENTITY_HELPER}" ]] || die 'host identity helper must be executable'
  "${PYTHON}" -I -B "${HOST_IDENTITY_HELPER}" --check >/dev/null \
    || die 'host identity helper check failed'
  "${PYTHON}" -I -B "${BINARY_VERIFIER_SOURCE}" --check >/dev/null \
    || die 'cloudflared binary verifier check failed'
  printf 'install-cloudflare-tunnel check: ok\n'
}

if [[ "${1:-}" == "--check" ]]; then
  offline_check
  exit 0
fi
if [[ "${1:-}" == "--install-under-wrapper" ]]; then
  [[ $# -eq 2 && "${2}" =~ ^[1-9][0-9]*$ && "${2}" == "${PPID}" \
      && "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die 'invalid internal Tunnel installer invocation'
  rollback_owned_by_wrapper=1
else
  [[ $# -eq 0 || "${1:-}" == "--install" ]] \
    || die 'usage: install-cloudflare-tunnel.sh [--check|--install]'
fi
[[ ${EUID} -eq 0 ]] || die 'run the installer as root on the target droplet'
offline_check >/dev/null

actual_host="$(hostname --short)"
[[ "${actual_host}" == "${LIL_TWEAK_EXPECTED_HOST:-${EXPECTED_HOST}}" ]] \
  || die "refusing to install on unexpected host: ${actual_host}"

tunnel_id="${LIL_TWEAK_TUNNEL_ID:-}"
core_hostname="${LIL_TWEAK_CORE_HOSTNAME:-}"
credentials_source="${LIL_TWEAK_TUNNEL_CREDENTIALS:-}"
cloudflared_sha256="${LIL_TWEAK_CLOUDFLARED_SHA256:-}"
rollback_receipt="${LIL_TWEAK_ROLLBACK_RECEIPT:-}"
rollback_manifest_sha256="${ROLLBACK_MANIFEST_SHA256:-}"
uuid_pattern='^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
hostname_pattern='^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
[[ "${tunnel_id}" =~ ${uuid_pattern} ]] || die 'LIL_TWEAK_TUNNEL_ID must be a lowercase UUID'
[[ ${#core_hostname} -le 253 && "${core_hostname}" =~ ${hostname_pattern} ]] \
  || die 'LIL_TWEAK_CORE_HOSTNAME must be a lowercase FQDN'
[[ "${credentials_source}" == /* ]] \
  || die 'LIL_TWEAK_TUNNEL_CREDENTIALS must be an absolute file'
[[ "${cloudflared_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'LIL_TWEAK_CLOUDFLARED_SHA256 must be a lowercase SHA-256 digest'
[[ "${rollback_receipt}" =~ ^/var/lib/lil-tweak-release-rollback/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ ]] \
  || die 'LIL_TWEAK_ROLLBACK_RECEIPT has an invalid production path'
[[ "${rollback_manifest_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'ROLLBACK_MANIFEST_SHA256 must be a lowercase SHA-256 digest'
if [[ -z "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" ]]; then
  exec "${PYTHON}" -I -B "${ROLLBACK_HELPER}" lease-exec \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    -- "${SCRIPT_DIR}/install-cloudflare-tunnel.sh" --install
fi
"${PYTHON}" -I -B "${ROLLBACK_HELPER}" lease-exec \
  --receipt "${rollback_receipt}" \
  --expected-manifest-sha256 "${rollback_manifest_sha256}" \
  -- /bin/true >/dev/null \
  || die 'verified rollback lease is required'
"${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" verify \
  --receipt "${rollback_receipt}" \
  --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null \
  || die 'rollback receipt validation failed'
if [[ ${rollback_owned_by_wrapper} -eq 0 ]]; then
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" verify-fresh-install \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null 2>&1 \
    || die 'fresh installation preflight failed'
fi
credentials_snapshot="$(mktemp -p /tmp lil-tweak-tunnel-credentials.XXXXXXXX.json)"
chmod 0600 "${credentials_snapshot}"
"${PYTHON}" -I -B "${VALIDATOR}" \
  --source "${credentials_source}" \
  --tunnel-id "${tunnel_id}" \
  --snapshot "${credentials_snapshot}" \
  || die 'invalid Tunnel credential file'
unset credentials_source
"${PYTHON}" -I -B "${BINARY_VERIFIER_SOURCE}" --expected-sha256 "${cloudflared_sha256}" \
  || die 'cloudflared binary digest mismatch'
mutation_started=1
if ! id "${TUNNEL_USER}" >/dev/null 2>&1; then
  useradd --system --user-group --home-dir /var/lib/lil-tweak-tunnel --create-home \
    --shell /usr/sbin/nologin "${TUNNEL_USER}"
fi
"${PYTHON}" -I -B "${HOST_IDENTITY_HELPER}" --user "${TUNNEL_USER}" >/dev/null 2>&1 \
  || die 'Tunnel requires a unique locked dedicated host identity'
tunnel_gid="$(id -g "${TUNNEL_USER}")"

staging_file="$(mktemp -p /tmp lil-tweak-cloudflared.XXXXXXXX.yml)"
chmod 0600 "${staging_file}"
sed -e "s|__TUNNEL_ID__|${tunnel_id}|g" -e "s|__CORE_HOSTNAME__|${core_hostname}|g" \
  "${TEMPLATE}" >"${staging_file}"
unit_staging_file="$(mktemp -p /tmp lil-tweak-cloudflared-unit.XXXXXXXX.service)"
chmod 0600 "${unit_staging_file}"
sed -e "s|@@LIL_TWEAK_CLOUDFLARED_SHA256@@|${cloudflared_sha256}|g" \
  "${UNIT}" >"${unit_staging_file}"
grep -Fq '@@LIL_TWEAK_CLOUDFLARED_SHA256@@' "${unit_staging_file}" \
  && die 'cloudflared unit digest rendering failed'

authorize_release_file() {
  local logical_path="$1" source_path="$2" mode="$3" uid="$4" gid="$5"
  "${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" authorize-file \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    --path "${logical_path}" --source "${source_path}" --mode "${mode}" \
    --uid "${uid}" --gid "${gid}" >/dev/null
}

authorize_release_file "${CONFIG_DIR}/tunnel.json" "${credentials_snapshot}" \
  0640 0 "${tunnel_gid}"
authorize_release_file "${CONFIG_DIR}/config.yml" "${staging_file}" \
  0640 0 "${tunnel_gid}"
authorize_release_file "${BINARY_VERIFIER_TARGET}" "${BINARY_VERIFIER_SOURCE}" \
  0755 0 0
authorize_release_file /etc/systemd/system/lil-tweak-cloudflared.service "${unit_staging_file}" \
  0644 0 0

install -d -m 0750 -o root -g "${TUNNEL_USER}" "${CONFIG_DIR}"
install -d -m 0755 -o root -g root /usr/local/libexec/lil-tweak
install -D -m 0640 -o root -g "${TUNNEL_USER}" \
  "${credentials_snapshot}" "${CONFIG_DIR}/tunnel.json"
install -D -m 0640 -o root -g "${TUNNEL_USER}" "${staging_file}" "${CONFIG_DIR}/config.yml"
install -D -m 0755 -o root -g root "${BINARY_VERIFIER_SOURCE}" "${BINARY_VERIFIER_TARGET}"
install -D -m 0644 -o root -g root "${unit_staging_file}" /etc/systemd/system/lil-tweak-cloudflared.service

(
  exec_without_rollback_lease /usr/sbin/runuser --user "${TUNNEL_USER}" -- \
    /usr/bin/env -i \
    "HOME=/var/lib/lil-tweak-tunnel" "USER=${TUNNEL_USER}" "LOGNAME=${TUNNEL_USER}" \
    "PATH=/usr/bin:/bin" "LC_ALL=C" \
    "${PYTHON}" -I -B "${BINARY_VERIFIER_TARGET}" --expected-sha256 "${cloudflared_sha256}" \
    --execute -- --config "${CONFIG_DIR}/config.yml" tunnel ingress validate
)
systemctl daemon-reload
systemctl enable lil-tweak-cloudflared.service
systemctl restart lil-tweak-cloudflared.service
printf 'Cloudflare Tunnel installed; confirm Access denies a headerless request before production routing.\n'
