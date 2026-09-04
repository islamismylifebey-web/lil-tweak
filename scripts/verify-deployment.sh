#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SERVICE_USER="lil-tweak"
SERVICE_HOME="/var/lib/lil-tweak"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
READY_PROBE="${PROJECT_DIR}/deploy/verify_ready.py"
RUNTIME_PROBE="${PROJECT_DIR}/deploy/verify_runtime.py"
R2_PROBE="${PROJECT_DIR}/deploy/verify_r2.py"
DATA_INTEGRITY="${PROJECT_DIR}/scripts/verify-data-integrity.sh"
QUALIFICATION="${PROJECT_DIR}/scripts/lil-tweak-qualification.py"

die() {
  printf 'verify-deployment: %s\n' "$*" >&2
  exit 1
}

offline_check() {
  [[ -f "${READY_PROBE}" && -f "${RUNTIME_PROBE}" && -f "${R2_PROBE}" \
      && -f "${DATA_INTEGRITY}" && -f "${QUALIFICATION}" && ! -L "${QUALIFICATION}" ]] \
    || die 'missing deployment probe'
  python3 "${READY_PROBE}" --check >/dev/null
  python3 "${RUNTIME_PROBE}" --check >/dev/null
  python3 "${R2_PROBE}" --check >/dev/null
  bash "${DATA_INTEGRITY}" --check >/dev/null
  python3 "${QUALIFICATION}" --check >/dev/null
  grep -Fq '127.0.0.1:8017/healthz' "${BASH_SOURCE[0]}" \
    || die 'loopback health probe is missing'
  ! grep -Eq 'curl[[:space:]]+[^#]*(--insecure|-k)([[:space:]]|$)' "${BASH_SOURCE[0]}" \
    || die 'TLS verification may not be disabled'
  printf 'verify-deployment check: ok\n'
}

if [[ "${1:-}" == "--check" ]]; then
  offline_check
  exit 0
fi
[[ $# -eq 0 ]] || die 'usage: verify-deployment.sh [--check]'
offline_check >/dev/null

command -v curl >/dev/null || die 'curl is required'
command -v ss >/dev/null || die 'ss is required'
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

for unit in podman.socket lil-tweak-postgres.service lil-tweak-core.service; do
  as_service systemctl --user is-active --quiet "${unit}" || die "inactive unit: ${unit}"
done

core_image="$(as_service podman inspect lil-tweak-core --format '{{.ImageName}}')"
postgres_image="$(as_service podman inspect lil-tweak-postgres --format '{{.ImageName}}')"
[[ "${core_image}" =~ @sha256:[0-9a-fA-F]{64}$ ]] || die 'core image is not digest-pinned'
[[ "${postgres_image}" =~ @sha256:[0-9a-fA-F]{64}$ ]] || die 'PostgreSQL image is not digest-pinned'
runner_image="$(awk -F= '$1 == "LIL_TWEAK_RUNNER_IMAGE" { sub(/^[^=]*=/, ""); print }' \
  "${SERVICE_HOME}/.config/lil-tweak/core.env")"
[[ "${runner_image}" =~ @sha256:[0-9a-fA-F]{64}$ ]] || die 'runner image is not digest-pinned'
as_service podman image exists "${runner_image}" || die 'runner image is not present locally'

core_networks="$(as_service podman inspect lil-tweak-core --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}')"
postgres_networks="$(as_service podman inspect lil-tweak-postgres --format '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}')"
[[ "${core_networks}" == "lil-tweak-private " ]] || die 'core joined an unexpected network'
[[ "${postgres_networks}" == "lil-tweak-private " ]] || die 'PostgreSQL joined an unexpected network'

ss -lnt | grep -Eq '[[:space:]]127\.0\.0\.1:8017[[:space:]]' \
  || die 'core is not listening on the loopback address'
! ss -lnt | grep -Eq '[[:space:]](0\.0\.0\.0|\[::\]):8017[[:space:]]' \
  || die 'core port is exposed on a public interface'

health_payload="$(curl --fail --silent --show-error --max-time 5 \
  http://127.0.0.1:8017/healthz)"
[[ "${health_payload}" == '{"status":"ok"}' || "${health_payload}" == '{"status": "ok"}' ]] \
  || die 'unexpected health response'

as_service python3 "${READY_PROBE}" "${SERVICE_HOME}/.config/lil-tweak/core.env"
as_service python3 "${RUNTIME_PROBE}" "${SERVICE_HOME}/.config/lil-tweak/core.env"
bash "${DATA_INTEGRITY}"

case "${LIL_TWEAK_VERIFY_R2:-0}" in
  0) ;;
  1) as_service podman exec lil-tweak-core python /app/deploy/verify_r2.py ;;
  *) die 'LIL_TWEAK_VERIFY_R2 must be 0 or 1' ;;
esac

max_workers="$(as_service podman inspect lil-tweak-core \
  --format '{{index .Config.Labels "com.galor.lil-tweak.max-concurrent-jobs"}}')"
[[ "${max_workers}" == "1" ]] || die 'core concurrency is not locked to one job'

printf 'deployment verification: ok\n'
