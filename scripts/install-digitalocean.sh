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

SERVICE_USER="lil-tweak"
SERVICE_HOME="/var/lib/lil-tweak"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
QUADLET_SOURCE="${PROJECT_DIR}/deploy/quadlet"
MIGRATION_001_SOURCE="${PROJECT_DIR}/core/migrations/001_initial.sql"
MIGRATION_002_SOURCE="${PROJECT_DIR}/core/migrations/002_fencing.sql"
MIGRATION_003_SOURCE="${PROJECT_DIR}/core/migrations/003_test_world.sql"
ROLLBACK_HELPER="${PROJECT_DIR}/scripts/lil-tweak-rollback.py"
RELEASE_HELPER="${PROJECT_DIR}/scripts/lil-tweak-release.py"
SECRET_SNAPSHOT_HELPER="${PROJECT_DIR}/scripts/lil-tweak-secret-snapshot.py"
HOST_IDENTITY_HELPER="${PROJECT_DIR}/scripts/lil-tweak-host-identity.py"
SERVICE_FILES_HELPER="${PROJECT_DIR}/scripts/lil-tweak-service-files.py"
TARGET_HELPER="${PROJECT_DIR}/scripts/lil-tweak-digitalocean-target.py"
runtime_auth_file=""
registry_auth_snapshot=""
secret_snapshot_dir=""
staging_dir=""
rollback_receipt=""
rollback_manifest_sha256=""
service_uid=""
service_gid=""
mutation_started=0
rollback_attempted=0
rollback_owned_by_wrapper=0

remove_runtime_auth() {
  [[ -n "${runtime_auth_file}" && "${service_uid}" =~ ^[1-9][0-9]*$ \
      && "${service_gid}" =~ ^[1-9][0-9]*$ ]] || return 1
  "${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" remove-runtime-auth \
    --path "${runtime_auth_file}" --uid "${service_uid}" --gid "${service_gid}" \
    >/dev/null 2>&1
}

exec_without_rollback_lease() {
  local lease_fd="${LIL_TWEAK_ROLLBACK_LEASE_FD:-}"
  [[ $# -gt 0 && "${lease_fd}" =~ ^(0|[1-9][0-9]*)$ ]] || return 1
  exec {lease_fd}>&-
  unset LIL_TWEAK_ROLLBACK_LEASE_FD
  exec "$@"
}

cleanup_release_state() {
  local cleanup_status=0
  if [[ -n "${runtime_auth_file}" ]]; then
    remove_runtime_auth || cleanup_status=1
  fi
  if [[ -n "${registry_auth_snapshot}" \
      && "${registry_auth_snapshot}" == /tmp/lil-tweak-registry-auth.* ]]; then
    rm -f -- "${registry_auth_snapshot}" || cleanup_status=1
    [[ ! -e "${registry_auth_snapshot}" && ! -L "${registry_auth_snapshot}" ]] \
      || cleanup_status=1
  fi
  if [[ -n "${secret_snapshot_dir}" ]]; then
    if [[ "${secret_snapshot_dir}" =~ ^/tmp/lil-tweak-secrets\.[A-Za-z0-9]{8}$ ]]; then
      rm -rf -- "${secret_snapshot_dir}" || cleanup_status=1
      [[ ! -e "${secret_snapshot_dir}" && ! -L "${secret_snapshot_dir}" ]] \
        || cleanup_status=1
    else
      cleanup_status=1
    fi
  fi
  if [[ -n "${staging_dir}" && "${staging_dir}" == /tmp/lil-tweak-install.* ]]; then
    rm -rf -- "${staging_dir}" || cleanup_status=1
    [[ ! -e "${staging_dir}" && ! -L "${staging_dir}" ]] || cleanup_status=1
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
  printf 'install-digitalocean: %s\n' "$*" >&2
  exit 1
}

offline_check() {
  local required
  for required in \
    "${PROJECT_DIR}/deploy/Containerfile.core" \
    "${PROJECT_DIR}/deploy/Containerfile.runner" \
    "${PROJECT_DIR}/deploy/postgres-bootstrap.sql" \
    "${PROJECT_DIR}/deploy/postgres-grants.sql" \
    "${PROJECT_DIR}/deploy/lil-tweak-core.service.d/hardening.conf" \
    "${PROJECT_DIR}/deploy/lil-tweak-postgres.service.d/hardening.conf" \
    "${QUADLET_SOURCE}/lil-tweak-core.container" \
    "${QUADLET_SOURCE}/lil-tweak-postgres.container" \
    "${QUADLET_SOURCE}/lil-tweak.network" \
    "${QUADLET_SOURCE}/lil-tweak-data.volume" \
    "${QUADLET_SOURCE}/lil-tweak-postgres-data.volume" \
    "${MIGRATION_001_SOURCE}" \
    "${MIGRATION_002_SOURCE}" \
    "${MIGRATION_003_SOURCE}" \
    "${ROLLBACK_HELPER}" \
    "${RELEASE_HELPER}" \
    "${SECRET_SNAPSHOT_HELPER}" \
    "${HOST_IDENTITY_HELPER}" \
    "${SERVICE_FILES_HELPER}" \
    "${TARGET_HELPER}"
  do
    [[ -f "${required}" ]] || die "missing deployment input: ${required}"
  done
  grep -Fq '@@LIL_TWEAK_CORE_IMAGE@@' "${QUADLET_SOURCE}/lil-tweak-core.container" \
    || die 'core image placeholder is missing'
  grep -Fq '@@LIL_TWEAK_POSTGRES_IMAGE@@' "${QUADLET_SOURCE}/lil-tweak-postgres.container" \
    || die 'PostgreSQL image placeholder is missing'
  [[ ! -L "${ROLLBACK_HELPER}" && -x "${ROLLBACK_HELPER}" ]] \
    || die 'rollback helper must be an executable regular file'
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" --check >/dev/null \
    || die 'rollback helper check failed'
  [[ -f "${RELEASE_HELPER}" && ! -L "${RELEASE_HELPER}" \
      && -x "${RELEASE_HELPER}" ]] \
    || die 'release helper must be an executable regular file'
  "${PYTHON}" -I -B "${RELEASE_HELPER}" --help >/dev/null \
    || die 'release helper check failed'
  [[ ! -L "${SECRET_SNAPSHOT_HELPER}" && -x "${SECRET_SNAPSHOT_HELPER}" ]] \
    || die 'secret snapshot helper must be an executable regular file'
  "${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" --check >/dev/null \
    || die 'secret snapshot helper check failed'
  [[ ! -L "${HOST_IDENTITY_HELPER}" && -x "${HOST_IDENTITY_HELPER}" ]] \
    || die 'host identity helper must be an executable regular file'
  "${PYTHON}" -I -B "${HOST_IDENTITY_HELPER}" --check >/dev/null \
    || die 'host identity helper check failed'
  [[ ! -L "${SERVICE_FILES_HELPER}" && -x "${SERVICE_FILES_HELPER}" ]] \
    || die 'service files helper must be an executable regular file'
  "${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" --check >/dev/null \
    || die 'service files helper check failed'
  [[ ! -L "${TARGET_HELPER}" && -x "${TARGET_HELPER}" ]] \
    || die 'DigitalOcean target helper must be an executable regular file'
  "${PYTHON}" -I -B "${TARGET_HELPER}" --check >/dev/null \
    || die 'DigitalOcean target helper check failed'
  printf 'install-digitalocean check: ok\n'
}

if [[ "${1:-}" == "--check" ]]; then
  offline_check
  exit 0
fi
if [[ "${1:-}" == "--install-under-wrapper" ]]; then
  [[ $# -eq 2 && "${2}" =~ ^[1-9][0-9]*$ && "${2}" == "${PPID}" \
      && "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" =~ ^(0|[1-9][0-9]*)$ ]] \
    || die 'invalid internal core installer invocation'
  rollback_owned_by_wrapper=1
else
  [[ $# -eq 0 || "${1:-}" == "--install" ]] \
    || die 'usage: install-digitalocean.sh [--check|--install]'
fi

[[ ${EUID} -eq 0 ]] || die 'run the installer as root on the target droplet'
offline_check >/dev/null
"${PYTHON}" -I -B "${TARGET_HELPER}" >/dev/null 2>&1 \
  || die 'DigitalOcean target verification failed'

core_image="${LIL_TWEAK_CORE_IMAGE:-}"
postgres_image="${LIL_TWEAK_POSTGRES_IMAGE:-}"
secrets_source="${LIL_TWEAK_SECRETS_SOURCE:-}"
registry_auth_source="${LIL_TWEAK_REGISTRY_AUTH_SOURCE:-}"
rollback_receipt="${LIL_TWEAK_ROLLBACK_RECEIPT:-}"
rollback_manifest_sha256="${ROLLBACK_MANIFEST_SHA256:-}"
source_manifest="${LIL_TWEAK_SOURCE_MANIFEST:-}"
runtime_manifest="${LIL_TWEAK_RUNTIME_MANIFEST:-}"
runtime_manifest_sha256="${LIL_TWEAK_RUNTIME_MANIFEST_SHA256:-}"
image_pattern='^[a-z0-9._-]+([.:][a-z0-9._-]+)?/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$'
"${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" validate-images \
  --image "${core_image}" --image "${postgres_image}" >/dev/null 2>&1 \
  || die 'core and PostgreSQL images must use strict digest-pinned references'
[[ -n "${secrets_source}" && "${secrets_source}" == /* && -d "${secrets_source}" ]] \
  || die 'LIL_TWEAK_SECRETS_SOURCE must be an absolute directory'
[[ "${rollback_receipt}" =~ ^/var/lib/lil-tweak-release-rollback/[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$ ]] \
  || die 'LIL_TWEAK_ROLLBACK_RECEIPT has an invalid production path'
[[ "${rollback_manifest_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'ROLLBACK_MANIFEST_SHA256 must be a lowercase SHA-256 digest'
[[ -n "${source_manifest}" && "${source_manifest}" == /* ]] \
  || die 'LIL_TWEAK_SOURCE_MANIFEST must be an absolute file'
[[ -n "${runtime_manifest}" && "${runtime_manifest}" == /* ]] \
  || die 'LIL_TWEAK_RUNTIME_MANIFEST must be an absolute file'
[[ "${runtime_manifest_sha256}" =~ ^[0-9a-f]{64}$ ]] \
  || die 'LIL_TWEAK_RUNTIME_MANIFEST_SHA256 must be a lowercase SHA-256 digest'
if [[ -z "${LIL_TWEAK_ROLLBACK_LEASE_FD:-}" ]]; then
  exec "${PYTHON}" -I -B "${ROLLBACK_HELPER}" lease-exec \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    -- "${SCRIPT_DIR}/install-digitalocean.sh" --install
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
"${PYTHON}" -I -B "${ROLLBACK_HELPER}" verify-fresh-install \
  --receipt "${rollback_receipt}" \
  --expected-manifest-sha256 "${rollback_manifest_sha256}" >/dev/null 2>&1 \
  || die 'fresh installation preflight failed'

secret_snapshot_dir="$(mktemp -d -p /tmp lil-tweak-secrets.XXXXXXXX)"
chmod 0700 "${secret_snapshot_dir}"
runner_image="$("${PYTHON}" -I -B "${SECRET_SNAPSHOT_HELPER}" snapshot \
  --source "${secrets_source}" --destination "${secret_snapshot_dir}" 2>/dev/null)" \
  || die 'secret snapshot validation failed'
[[ "${runner_image}" =~ ${image_pattern} ]] || die 'snapshot runner image must be digest-pinned'
"${PYTHON}" -I -B "${RELEASE_HELPER}" verify-runtime-install \
  --source-manifest "${source_manifest}" \
  --source-dir "${PROJECT_DIR}" \
  --runtime-manifest "${runtime_manifest}" \
  --runtime-manifest-sha256 "${runtime_manifest_sha256}" \
  --rollback-manifest "${rollback_receipt}/manifest.json" \
  --rollback-manifest-sha256 "${rollback_manifest_sha256}" \
  --core-image "${core_image}" \
  --postgres-image "${postgres_image}" \
  --runner-image "${runner_image}" >/dev/null 2>&1 \
  || die 'runtime installation provenance rejected'
core_env_snapshot="${secret_snapshot_dir}/core.env"
admin_password_snapshot="${secret_snapshot_dir}/postgres-admin-password"
app_password_snapshot="${secret_snapshot_dir}/postgres-app-password"
migrator_password_snapshot="${secret_snapshot_dir}/postgres-migrator-password"
unset secrets_source LIL_TWEAK_SECRETS_SOURCE

[[ "${registry_auth_source}" == /* ]] \
  || die 'LIL_TWEAK_REGISTRY_AUTH_SOURCE must be an absolute file'
registry_auth_snapshot="$(mktemp -p /tmp lil-tweak-registry-auth.XXXXXXXX)"
chmod 0600 "${registry_auth_snapshot}"
"${PYTHON}" -I -B - "${registry_auth_source}" "${registry_auth_snapshot}" \
  "${core_image}" "${postgres_image}" "${runner_image}" 2>/dev/null <<'PY' \
  || die 'registry authentication file is invalid'
import json
import os
import stat
import sys


def reject(_value):
    raise ValueError("invalid")


def pairs(values):
    result = {}
    for key, value in values:
        if key in result:
            raise ValueError("invalid")
        result[key] = value
    return result


path = sys.argv[1]
flags = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
descriptor = os.open(path, flags)
try:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("invalid")
    if before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600:
        raise ValueError("invalid")
    if before.st_size < 2 or before.st_size > 65536:
        raise ValueError("invalid")
    data = b""
    while len(data) <= before.st_size:
        chunk = os.read(descriptor, before.st_size + 1 - len(data))
        if not chunk:
            break
        data += chunk
    after = os.fstat(descriptor)
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(data) != before.st_size or any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError("invalid")
finally:
    os.close(descriptor)

document = json.loads(
    data.decode("utf-8"),
    object_pairs_hook=pairs,
    parse_constant=reject,
)
if not isinstance(document, dict) or set(document) != {"auths"}:
    raise ValueError("invalid")
auths = document["auths"]
registries = {reference.split("/", 1)[0] for reference in sys.argv[3:]}
if not isinstance(auths, dict) or set(auths) != registries:
    raise ValueError("invalid")
for registry, value in auths.items():
    if not isinstance(registry, str) or not isinstance(value, dict) or not value:
        raise ValueError("invalid")
    if not set(value).issubset({"auth", "identitytoken"}):
        raise ValueError("invalid")
    if not all(isinstance(item, str) and item for item in value.values()):
        raise ValueError("invalid")

destination = sys.argv[2]
output = os.open(
    destination,
    os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    target = os.fstat(output)
    if not stat.S_ISREG(target.st_mode) or target.st_nlink != 1 or target.st_uid != 0:
        raise ValueError("invalid")
    os.fchmod(output, 0o600)
    written = 0
    while written < len(data):
        count = os.write(output, data[written:])
        if count <= 0:
            raise ValueError("invalid")
        written += count
    os.fsync(output)
finally:
    os.close(output)
PY

mutation_started=1

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --create-home --home-dir "${SERVICE_HOME}" --shell /usr/sbin/nologin \
    --user-group "${SERVICE_USER}"
fi
"${PYTHON}" -I -B "${HOST_IDENTITY_HELPER}" --user "${SERVICE_USER}" >/dev/null 2>&1 \
  || die 'lil-tweak requires a unique locked dedicated host identity'
service_uid="$(id -u "${SERVICE_USER}")"
service_gid="$(id -g "${SERVICE_USER}")"

staging_dir="$(mktemp -d -p /tmp lil-tweak-install.XXXXXXXX)"
chmod 0700 "${staging_dir}"
install -d -m 0700 \
  "${staging_dir}/.config/lil-tweak" \
  "${staging_dir}/.config/containers/systemd" \
  "${staging_dir}/.config/systemd/user/lil-tweak-core.service.d" \
  "${staging_dir}/.config/systemd/user/lil-tweak-postgres.service.d" \
  "${staging_dir}/.local/share/lil-tweak/migrations"
install -D -m 0600 "${core_env_snapshot}" \
  "${staging_dir}/.config/lil-tweak/core.env"
install -D -m 0400 "${MIGRATION_001_SOURCE}" \
  "${staging_dir}/.local/share/lil-tweak/migrations/001_initial.sql"
install -D -m 0400 "${MIGRATION_002_SOURCE}" \
  "${staging_dir}/.local/share/lil-tweak/migrations/002_fencing.sql"
install -D -m 0400 "${MIGRATION_003_SOURCE}" \
  "${staging_dir}/.local/share/lil-tweak/migrations/003_test_world.sql"
install -D -m 0400 "${PROJECT_DIR}/deploy/postgres-bootstrap.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/postgres-bootstrap.sql"
install -D -m 0400 "${PROJECT_DIR}/deploy/postgres-grants.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/postgres-grants.sql"
sed "s|@@LIL_TWEAK_CORE_IMAGE@@|${core_image}|g" \
  "${QUADLET_SOURCE}/lil-tweak-core.container" \
  >"${staging_dir}/.config/containers/systemd/lil-tweak-core.container"
sed "s|@@LIL_TWEAK_POSTGRES_IMAGE@@|${postgres_image}|g" \
  "${QUADLET_SOURCE}/lil-tweak-postgres.container" \
  >"${staging_dir}/.config/containers/systemd/lil-tweak-postgres.container"
chmod 0644 \
  "${staging_dir}/.config/containers/systemd/lil-tweak-core.container" \
  "${staging_dir}/.config/containers/systemd/lil-tweak-postgres.container"
for unit in lil-tweak.network lil-tweak-data.volume lil-tweak-postgres-data.volume; do
  install -D -m 0644 "${QUADLET_SOURCE}/${unit}" \
    "${staging_dir}/.config/containers/systemd/${unit}"
done
install -D -m 0644 \
  "${PROJECT_DIR}/deploy/lil-tweak-core.service.d/hardening.conf" \
  "${staging_dir}/.config/systemd/user/lil-tweak-core.service.d/hardening.conf"
install -D -m 0644 \
  "${PROJECT_DIR}/deploy/lil-tweak-postgres.service.d/hardening.conf" \
  "${staging_dir}/.config/systemd/user/lil-tweak-postgres.service.d/hardening.conf"

authorize_release_file() {
  local logical_path="$1" source_path="$2" mode="$3" uid="$4" gid="$5"
  "${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" authorize-file \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    --path "${logical_path}" --source "${source_path}" --mode "${mode}" \
    --uid "${uid}" --gid "${gid}" >/dev/null
}

authorize_release_file "${SERVICE_HOME}/.config/lil-tweak/core.env" \
  "${staging_dir}/.config/lil-tweak/core.env" 0600 "${service_uid}" "${service_gid}"
authorize_release_file "${SERVICE_HOME}/.local/share/lil-tweak/migrations/001_initial.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/001_initial.sql" \
  0400 "${service_uid}" "${service_gid}"
authorize_release_file "${SERVICE_HOME}/.local/share/lil-tweak/migrations/002_fencing.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/002_fencing.sql" \
  0400 "${service_uid}" "${service_gid}"
authorize_release_file "${SERVICE_HOME}/.local/share/lil-tweak/migrations/003_test_world.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/003_test_world.sql" \
  0400 "${service_uid}" "${service_gid}"
authorize_release_file "${SERVICE_HOME}/.local/share/lil-tweak/migrations/postgres-bootstrap.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/postgres-bootstrap.sql" \
  0400 "${service_uid}" "${service_gid}"
authorize_release_file "${SERVICE_HOME}/.local/share/lil-tweak/migrations/postgres-grants.sql" \
  "${staging_dir}/.local/share/lil-tweak/migrations/postgres-grants.sql" \
  0400 "${service_uid}" "${service_gid}"
for unit in lil-tweak-core.container lil-tweak-postgres.container lil-tweak.network \
  lil-tweak-data.volume lil-tweak-postgres-data.volume; do
  authorize_release_file "${SERVICE_HOME}/.config/containers/systemd/${unit}" \
    "${staging_dir}/.config/containers/systemd/${unit}" \
    0644 "${service_uid}" "${service_gid}"
done
authorize_release_file \
  "${SERVICE_HOME}/.config/systemd/user/lil-tweak-core.service.d/hardening.conf" \
  "${staging_dir}/.config/systemd/user/lil-tweak-core.service.d/hardening.conf" \
  0644 "${service_uid}" "${service_gid}"
authorize_release_file \
  "${SERVICE_HOME}/.config/systemd/user/lil-tweak-postgres.service.d/hardening.conf" \
  "${staging_dir}/.config/systemd/user/lil-tweak-postgres.service.d/hardening.conf" \
  0644 "${service_uid}" "${service_gid}"

loginctl enable-linger "${SERVICE_USER}"
systemctl start "user@${service_uid}.service"
[[ -d "/run/user/${service_uid}" ]] || die 'systemd user runtime did not start'

as_service() (
  exec_without_rollback_lease /usr/sbin/runuser --user "${SERVICE_USER}" -- \
    /usr/bin/env -i \
    "HOME=${SERVICE_HOME}" "USER=${SERVICE_USER}" "LOGNAME=${SERVICE_USER}" \
    "PATH=/usr/bin:/bin" "LC_ALL=C" \
    "XDG_RUNTIME_DIR=/run/user/${service_uid}" \
    "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${service_uid}/bus" "$@"
)

runtime_auth_file="$("${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" stage-runtime-auth \
  --source "${registry_auth_snapshot}" --uid "${service_uid}" --gid "${service_gid}" \
  2>/dev/null)" || die 'runtime registry authentication staging failed'
[[ "${runtime_auth_file}" =~ ^/run/user/${service_uid}/lil-tweak-registry-auth\.[0-9a-f]{16}\.[0-9a-f]+\.[0-9a-f]+$ ]] \
  || die 'runtime registry authentication staging failed'
rm -f -- "${registry_auth_snapshot}"
[[ ! -e "${registry_auth_snapshot}" && ! -L "${registry_auth_snapshot}" ]] \
  || die 'registry authentication snapshot cleanup failed'
registry_auth_snapshot=""

verify_pulled_image() {
  local reference="$1" expected_digest digest repo_digests
  expected_digest="sha256:${reference##*@sha256:}"
  digest="$(as_service podman image inspect --format '{{.Digest}}' "${reference}")"
  [[ "${digest}" == "${expected_digest}" ]] || die 'pulled image digest mismatch'
  repo_digests="$(as_service podman image inspect \
    --format '{{range .RepoDigests}}{{println .}}{{end}}' "${reference}")"
  grep -Fxq -- "${reference}" <<<"${repo_digests}" \
    || die 'pulled image repository digest mismatch'
}

"${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" authorize-images \
  --receipt "${rollback_receipt}" \
  --expected-manifest-sha256 "${rollback_manifest_sha256}" \
  --core-reference "${core_image}" \
  --postgres-reference "${postgres_image}" \
  --runner-reference "${runner_image}" >/dev/null

for image in "${core_image}" "${postgres_image}" "${runner_image}"; do
  as_service podman pull --authfile "${runtime_auth_file}" "${image}" >/dev/null
  verify_pulled_image "${image}"
done
remove_runtime_auth || die 'runtime registry authentication cleanup failed'
runtime_auth_file=""

as_service systemctl --user enable --now podman.socket

authorize_release_object() {
  local kind="$1" name="$2" identity="$3"
  "${PYTHON}" -I -B "${PROJECT_DIR}/scripts/lil-tweak-rollback.py" authorize-object \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    --kind "${kind}" --name "${name}" --identity "${identity}" >/dev/null
}

finalize_release_object() {
  local kind="$1" name="$2" identity="$3"
  "${PYTHON}" -I -B "${ROLLBACK_HELPER}" finalize-object \
    --receipt "${rollback_receipt}" \
    --expected-manifest-sha256 "${rollback_manifest_sha256}" \
    --kind "${kind}" --name "${name}" --identity "${identity}" >/dev/null
}

authorize_release_object container lil-tweak-core "${core_image}"
authorize_release_object container lil-tweak-postgres "${postgres_image}"
authorize_release_object network lil-tweak-private lil-tweak-private
authorize_release_object secret lil-tweak-postgres-admin-password \
  lil-tweak-postgres-admin-password

"${PYTHON}" -I -B "${SERVICE_FILES_HELPER}" install-tree \
  --staging "${staging_dir}" --uid "${service_uid}" --gid "${service_gid}" \
  >/dev/null 2>&1 || die 'service file installation failed'

as_service podman secret create lil-tweak-postgres-admin-password - \
  <"${admin_password_snapshot}" >/dev/null
finalize_release_object secret lil-tweak-postgres-admin-password \
  lil-tweak-postgres-admin-password

as_service systemctl --user daemon-reload
as_service systemctl --user start lil-tweak-network.service
finalize_release_object network lil-tweak-private lil-tweak-private
as_service systemctl --user start lil-tweak-postgres.service
finalize_release_object container lil-tweak-postgres "${postgres_image}"

for _attempt in {1..30}; do
  if as_service podman exec lil-tweak-postgres pg_isready \
    --username lil_tweak_admin --dbname lil_tweak >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
as_service podman exec lil-tweak-postgres pg_isready \
  --username lil_tweak_admin --dbname lil_tweak >/dev/null \
  || die 'PostgreSQL did not become ready'

app_password="$(<"${app_password_snapshot}")"
migrator_password="$(<"${migrator_password_snapshot}")"
{
  printf "\\set app_role 'lil_tweak_app'\n"
  printf "\\set migrator_role 'lil_tweak_migrator'\n"
  printf "\\set app_password '%s'\n" "${app_password}"
  printf "\\set migrator_password '%s'\n" "${migrator_password}"
  sed -n '1,$p' "${PROJECT_DIR}/deploy/postgres-bootstrap.sql"
} | as_service podman exec --interactive lil-tweak-postgres psql \
  --username lil_tweak_admin --dbname lil_tweak --no-psqlrc
unset app_password migrator_password

schema_exists="$(as_service podman exec lil-tweak-postgres psql \
  --username lil_tweak_admin --dbname lil_tweak --no-psqlrc --tuples-only --no-align \
  --command "SELECT to_regclass('public.lil_tweak_schema_version') IS NOT NULL")"
if [[ "${schema_exists}" == "t" ]]; then
  schema_version="$(as_service podman exec lil-tweak-postgres psql \
    --username lil_tweak_admin --dbname lil_tweak --no-psqlrc --tuples-only --no-align \
    --command 'SELECT COALESCE(max(version), 0) FROM lil_tweak_schema_version')"
else
  schema_version="0"
fi
apply_migration() {
  local migration_path="$1"
  {
    printf 'SET ROLE lil_tweak_migrator;\n'
    sed -n '1,$p' "${migration_path}"
    printf 'RESET ROLE;\n'
  } | as_service podman exec --interactive lil-tweak-postgres psql \
    --username lil_tweak_admin --dbname lil_tweak --no-psqlrc --set ON_ERROR_STOP=on
}

if [[ "${schema_version}" != "0" && "${schema_version}" != "1" \
    && "${schema_version}" != "2" && "${schema_version}" != "3" ]]; then
  die "database schema ${schema_version} is newer than this release"
fi
if [[ "${schema_version}" == "0" ]]; then
  apply_migration "${MIGRATION_001_SOURCE}"
  schema_version="1"
fi
if [[ "${schema_version}" == "1" ]]; then
  apply_migration "${MIGRATION_002_SOURCE}"
  schema_version="2"
fi
if [[ "${schema_version}" == "2" ]]; then
  apply_migration "${MIGRATION_003_SOURCE}"
  schema_version="3"
fi
[[ "${schema_version}" == "3" ]] || die 'database did not reach schema version 3'

{
  printf "\\set app_role 'lil_tweak_app'\n"
  printf "\\set migrator_role 'lil_tweak_migrator'\n"
  sed -n '1,$p' "${PROJECT_DIR}/deploy/postgres-grants.sql"
} | as_service podman exec --interactive lil-tweak-postgres psql \
  --username lil_tweak_admin --dbname lil_tweak --no-psqlrc

as_service systemctl --user restart lil-tweak-core.service
finalize_release_object container lil-tweak-core "${core_image}"

printf 'Lil Tweak installed locally on 127.0.0.1:8017. Run verify-deployment.sh locally.\n'
