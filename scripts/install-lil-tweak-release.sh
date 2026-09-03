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

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SELF="${SCRIPT_DIR}/install-lil-tweak-release.sh"
CORE_INSTALLER="${SCRIPT_DIR}/install-digitalocean.sh"
TUNNEL_INSTALLER="${SCRIPT_DIR}/install-cloudflare-tunnel.sh"
ROLLBACK_HELPER="${SCRIPT_DIR}/lil-tweak-rollback.py"
rollback_receipt="${LIL_TWEAK_ROLLBACK_RECEIPT:-}"
rollback_manifest_sha256="${ROLLBACK_MANIFEST_SHA256:-}"
transaction_started=0
rollback_attempted=0

die() {
  printf 'install-lil-tweak-release: %s\n' "$*" >&2
  exit 1
}

offline_check() {
  local required
  for required in "${SELF}" "${CORE_INSTALLER}" "${TUNNEL_INSTALLER}" "${ROLLBACK_HELPER}"; do
    [[ -f "${required}" && ! -L "${required}" && -x "${required}" ]] \
      || die 'release transaction input is missing or unsafe'
  done
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" --check >/dev/null \
    || die 'rollback helper check failed'
  "${CORE_INSTALLER}" --check >/dev/null
  "${TUNNEL_INSTALLER}" --check >/dev/null
  printf 'install-lil-tweak-release check: ok\n'
}

finish_transaction() {
  local original_status=$? status
  status=${original_status}
  trap - EXIT HUP INT TERM
  if [[ ${status} -ne 0 && ${transaction_started} -eq 1 \
      && ${rollback_attempted} -eq 0 ]]; then
    rollback_attempted=1
    "${PYTHON}" -I -B "${ROLLBACK_HELPER}" restore \
      --receipt "${rollback_receipt}" \
      --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null \
      || { [[ ${original_status} -ne 0 ]] && status=${original_status} || status=1; }
  fi
  exit "${status}"
}

if [[ "${1:-}" == "--check" ]]; then
  [[ $# -eq 1 ]] || die 'usage: install-lil-tweak-release.sh [--check|--install]'
  offline_check
  exit 0
fi

if [[ "${1:-}" == "--under-lease" ]]; then
  [[ $# -eq 1 ]] || die 'invalid internal release invocation'
  [[ "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die 'verified rollback lease is required'
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" lease-exec \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    -- /bin/true >/dev/null \
    || die 'verified rollback lease is required'
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" verify-fresh-install \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null 2>&1 \
    || die 'fresh installation preflight failed'
  trap finish_transaction EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  transaction_started=1
  "${CORE_INSTALLER}" --install-under-wrapper "$$"
  "${TUNNEL_INSTALLER}" --install-under-wrapper "$$"
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" mark-completed \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null 2>&1 \
    || die 'release transaction completion failed'
  transaction_started=0
  printf 'Lil Tweak core and Tunnel installation transaction completed.\n'
  exit 0
fi

[[ $# -eq 0 || "${1:-}" == "--install" ]] \
  || die 'usage: install-lil-tweak-release.sh [--check|--install]'
[[ ${EUID} -eq 0 ]] || die 'run the release transaction as root on the target droplet'
offline_check >/dev/null
[[ "${rollback_receipt}" =~ ^/var/lib/lil-tweak-release-rollback/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ ]] \
  || die 'LIL_TWEAK_ROLLBACK_RECEIPT has an invalid production path'
[[ "${rollback_manifest_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'ROLLBACK_MANIFEST_SHA256 must be a lowercase SHA-256 digest'

exec "${PYTHON}" -I -B "${ROLLBACK_HELPER}" lease-exec \
  --receipt "${rollback_receipt}" \
  --expected-manifest-sha256 "${rollback_manifest_sha256}" \
  -- "${SELF}" --under-lease
