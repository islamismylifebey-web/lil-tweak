#!/usr/bin/env bash
set -Eeuo pipefail

test "$(id -u)" -eq 0
source_root="${1:?usage: provision_host.sh /path/to/exact/lil-tweak-checkout}"
test -d "$source_root/.git"
test -f /etc/liltweak-runner/credentials.json
test -f /etc/liltweak-runner/runner_signing_key.pem
test -f /etc/liltweak-runner/repository_deploy_key
test -f /etc/liltweak-runner/github_known_hosts

image_ref='python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36'
command -v docker >/dev/null || { echo 'existing Docker is required' >&2; exit 1; }
packages=()
command -v aa-exec >/dev/null || packages+=(apparmor-utils)
command -v apparmor_parser >/dev/null || packages+=(apparmor-utils)
command -v bwrap >/dev/null || packages+=(bubblewrap)
command -v git >/dev/null || packages+=(git)
command -v mount >/dev/null || packages+=(mount)
command -v python3 >/dev/null || packages+=(python3)
if ! python3 -m venv --help >/dev/null 2>&1; then packages+=(python3-venv); fi
if ((${#packages[@]})); then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
fi

id -u liltweak-job >/dev/null 2>&1 || useradd --uid 17001 --system --no-create-home --shell /usr/sbin/nologin liltweak-job
install -d -o root -g root -m 0755 /opt/liltweak-runner /opt/liltweak-runtime
install -d -o root -g root -m 0700 /var/lib/liltweak-runner/workspaces /var/lib/liltweak-runner/candidates

candidate_sha="$(git -C "$source_root" rev-parse HEAD)"
candidate_tree="$(git -C "$source_root" rev-parse 'HEAD^{tree}')"
[[ "$candidate_sha" =~ ^[0-9a-f]{40}$ ]]
[[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]]
test -z "$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)"
rm -rf /opt/liltweak-runner/app /opt/liltweak-runner/venv
install -d -o root -g root -m 0755 /opt/liltweak-runner/app
git -C "$source_root" archive --format=tar "$candidate_sha" | tar -xpf - -C /opt/liltweak-runner/app
python3 -m venv /opt/liltweak-runner/venv
/opt/liltweak-runner/venv/bin/pip install --disable-pip-version-check --no-input /opt/liltweak-runner/app

runtime_tmp="$(mktemp -d /opt/liltweak-runtime/.rootfs.XXXXXX)"
container_id=''
cleanup() {
  if [[ -n "$container_id" ]]; then docker rm -f "$container_id" >/dev/null 2>&1 || true; fi
  if mountpoint -q "$runtime_tmp/opt/liltweak-runner/app"; then umount "$runtime_tmp/opt/liltweak-runner/app"; fi
  if mountpoint -q "$runtime_tmp/opt/liltweak-runtime"; then umount "$runtime_tmp/opt/liltweak-runtime"; fi
  rm -rf -- "$runtime_tmp"
}
trap cleanup EXIT
docker pull "$image_ref"
container_id="$(docker create "$image_ref")"
docker export "$container_id" | tar -xpf - -C "$runtime_tmp"
docker rm "$container_id" >/dev/null
container_id=''
rm -rf /opt/liltweak-runtime/venv
mkdir -p "$runtime_tmp/usr/bin" "$runtime_tmp/opt/liltweak-runtime" "$runtime_tmp/opt/liltweak-runner/app"
install -d -o root -g root -m 0555 "$runtime_tmp/source" "$runtime_tmp/workspace"
ln -sfn /usr/local/bin/python3 "$runtime_tmp/usr/bin/python3"
resolver_source=/etc/resolv.conf
if [[ -f /run/systemd/resolve/resolv.conf ]]; then
  resolver_source=/run/systemd/resolve/resolv.conf
fi
rm -f "$runtime_tmp/etc/resolv.conf"
install -o root -g root -m 0644 "$resolver_source" "$runtime_tmp/etc/resolv.conf"
mount --bind /opt/liltweak-runtime "$runtime_tmp/opt/liltweak-runtime"
mount --bind /opt/liltweak-runner/app "$runtime_tmp/opt/liltweak-runner/app"
chroot "$runtime_tmp" /bin/sh -ceu 'apt-get update; apt-get install -y --no-install-recommends ca-certificates git; rm -rf /var/lib/apt/lists/*; python3 -m venv /opt/liltweak-runtime/venv; /opt/liltweak-runtime/venv/bin/pip install --disable-pip-version-check --no-input /opt/liltweak-runner/app "pytest>=8.4,<9" "ruff>=0.12,<1"'
umount "$runtime_tmp/opt/liltweak-runner/app"
umount "$runtime_tmp/opt/liltweak-runtime"

rm -rf /opt/liltweak-runtime/rootfs
mv "$runtime_tmp" /opt/liltweak-runtime/rootfs
runtime_tmp="$(mktemp -d /opt/liltweak-runtime/.done.XXXXXX)"
/opt/liltweak-runner/venv/bin/python -c 'from pathlib import Path; from runner.seccomp import build_seccomp_filter; Path("/opt/liltweak-runner/seccomp.bpf").write_bytes(build_seccomp_filter())'
chown root:root /opt/liltweak-runner/seccomp.bpf
chmod 0444 /opt/liltweak-runner/seccomp.bpf

install -o root -g root -m 0644 /opt/liltweak-runner/app/runner/liltweak-runner-job.apparmor /etc/apparmor.d/liltweak-runner-job
apparmor_parser -r /etc/apparmor.d/liltweak-runner-job
profile_sha="$(sha256sum /etc/apparmor.d/liltweak-runner-job | cut -d' ' -f1)"
venv_sha="$(find /opt/liltweak-runtime/venv -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
seccomp_sha="$(sha256sum /opt/liltweak-runner/seccomp.bpf | cut -d' ' -f1)"
python3 - "$image_ref" "$profile_sha" "$venv_sha" "$seccomp_sha" <<'PY'
import json, os, sys
path = '/opt/liltweak-runtime/rootfs/.liltweak-rootfs-manifest.json'
data = {'schema_version':'lil-tweak.runtime-rootfs/v1','image_ref':sys.argv[1],'apparmor_profile_sha256':sys.argv[2],'venv_sha256':sys.argv[3],'seccomp_sha256':sys.argv[4]}
fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o444)
os.write(fd, (json.dumps(data, sort_keys=True, separators=(',',':'))+'\n').encode())
os.close(fd)
PY
chown -R root:root /opt/liltweak-runner /opt/liltweak-runtime
chmod 0755 /opt/liltweak-runtime/rootfs
chmod 0444 /opt/liltweak-runtime/rootfs/.liltweak-rootfs-manifest.json
install -o root -g root -m 0644 /opt/liltweak-runner/app/runner/liltweak-runner.service /etc/systemd/system/liltweak-runner.service
systemctl daemon-reload
systemctl enable --now liltweak-runner.service
systemctl --no-pager --full status liltweak-runner.service
