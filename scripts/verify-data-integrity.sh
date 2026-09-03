#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SERVICE_USER="lil-tweak"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
INTEGRITY_SQL="${PROJECT_DIR}/deploy/postgres-integrity.sql"
EXPORT_SQL="${PROJECT_DIR}/deploy/postgres-normalized-export.sql"

die() {
  printf 'verify-data-integrity: %s\n' "$*" >&2
  exit 1
}

offline_check() {
  local required
  for required in "${INTEGRITY_SQL}" "${EXPORT_SQL}"; do
    [[ -f "${required}" && ! -L "${required}" ]] \
      || die "missing deployment input: ${required}"
  done
  grep -Fq 'TRANSACTION READ ONLY' "${INTEGRITY_SQL}" \
    || die 'integrity query must use a read-only transaction'
  grep -Fq 'TRANSACTION READ ONLY' "${EXPORT_SQL}" \
    || die 'normalized export must use a read-only transaction'
  ! grep -Eiq '\b(DELETE|UPDATE|INSERT|TRUNCATE|DROP|ALTER|CREATE)\b' \
    "${INTEGRITY_SQL}" "${EXPORT_SQL}" \
    || die 'verification SQL contains a mutating statement'
  printf 'verify-data-integrity check: ok\n'
}

if [[ "${1:-}" == "--check" ]]; then
  [[ $# -eq 1 ]] || die 'usage: verify-data-integrity.sh [--check|--snapshot ABSOLUTE_PATH|--compare ABSOLUTE_PATH]'
  offline_check
  exit 0
fi
offline_check >/dev/null

command -v sha256sum >/dev/null || die 'sha256sum is required'
id "${SERVICE_USER}" >/dev/null 2>&1 || die 'dedicated service user does not exist'
service_uid="$(id -u "${SERVICE_USER}")"

as_service() {
  if [[ "$(id -un)" == "${SERVICE_USER}" ]]; then
    env "XDG_RUNTIME_DIR=/run/user/${service_uid}" \
      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus" "$@"
  elif [[ ${EUID} -eq 0 ]]; then
    runuser --user "${SERVICE_USER}" -- \
      env "XDG_RUNTIME_DIR=/run/user/${service_uid}" \
      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus" "$@"
  else
    die 'run as root or the lil-tweak service user'
  fi
}

as_service podman container exists lil-tweak-postgres \
  || die 'isolated PostgreSQL container is unavailable'

run_integrity() {
  as_service podman exec --interactive lil-tweak-postgres psql \
    --username lil_tweak_admin --dbname lil_tweak --no-psqlrc \
    --set ON_ERROR_STOP=on <"${INTEGRITY_SQL}"
}

normalized_fingerprint() {
  local digest
  digest="$({
    as_service podman exec --interactive lil-tweak-postgres psql \
      --username lil_tweak_admin --dbname lil_tweak --no-psqlrc \
      --quiet --tuples-only --no-align --set ON_ERROR_STOP=on <"${EXPORT_SQL}"
  } | sha256sum)"
  digest="${digest%% *}"
  [[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || die 'could not fingerprint normalized rows'
  printf 'sha256:%s\n' "${digest}"
}

run_integrity

case "${1:-}" in
  '')
    printf 'normalized source/evidence integrity: ok\n'
    ;;
  --snapshot)
    [[ $# -eq 2 && "${2}" == /* ]] \
      || die 'snapshot path must be absolute'
    [[ ! -e "${2}" && ! -L "${2}" && -d "$(dirname -- "${2}")" ]] \
      || die 'snapshot path must be a new file in an existing directory'
    fingerprint="$(normalized_fingerprint)"
    (umask 077; set -o noclobber; printf '%s\n' "${fingerprint}" >"${2}") \
      || die 'could not create snapshot manifest'
    printf 'normalized-row snapshot manifest created: %s\n' "${2}"
    ;;
  --compare)
    [[ $# -eq 2 && "${2}" == /* && -f "${2}" && ! -L "${2}" ]] \
      || die 'comparison manifest must be an absolute regular file'
    [[ "$(stat --format='%s' -- "${2}")" -le 80 ]] \
      || die 'comparison manifest is invalid'
    IFS= read -r expected <"${2}" || die 'comparison manifest is empty'
    [[ "${expected}" =~ ^sha256:[0-9a-f]{64}$ ]] \
      || die 'comparison manifest is invalid'
    current="$(normalized_fingerprint)"
    [[ "${current}" == "${expected}" ]] \
      || die 'normalized rows differ from the backup manifest'
    printf 'normalized-row restore comparison: ok\n'
    ;;
  *)
    die 'usage: verify-data-integrity.sh [--check|--snapshot ABSOLUTE_PATH|--compare ABSOLUTE_PATH]'
    ;;
esac
