#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "qualification installer must run as root" >&2
  exit 1
fi

SOURCE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
RUNNER_USER=liltweak-runner
test "$#" -eq 0
id "$RUNNER_USER" >/dev/null

for path in \
  /usr/bin/bwrap \
  /usr/bin/prlimit \
  /usr/bin/python3 \
  /usr/bin/aa-exec \
  /usr/bin/git \
  /usr/bin/ssh \
  /usr/bin/mount \
  /usr/bin/umount \
  /opt/liltweak-runtime/rootfs \
  /opt/liltweak-runner/seccomp.bpf \
  /etc/apparmor.d/liltweak-runner-job \
  /etc/liltweak-runner/repository_deploy_key \
  /etc/liltweak-runner/github_known_hosts \
  /etc/liltweak-runner/runner_signing_key.pem
do
  test -e "$path" || { echo "missing shared runner prerequisite: $path" >&2; exit 1; }
done

install -d -o root -g root -m 0755 /opt/liltweak-qualification
install -d -o root -g root -m 0755 /opt/liltweak-qualification/bin
install -d -o root -g root -m 0755 /opt/liltweak-qualification/libexec
install -d -o root -g root -m 0700 /etc/liltweak-qualification
install -d -o root -g root -m 0700 /var/lib/liltweak-qualification
install -d -o root -g root -m 0700 /var/lib/liltweak-qualification/sessions
install -d -o root -g root -m 0700 /var/lib/liltweak-qualification/used

install -o root -g root -m 0555 "$SOURCE_ROOT/bin/collect" /opt/liltweak-qualification/bin/collect
install -o root -g root -m 0555 "$SOURCE_ROOT/bin/destroy" /opt/liltweak-qualification/bin/destroy
install -o root -g root -m 0500 "$SOURCE_ROOT/supervisor.py" /opt/liltweak-qualification/libexec/supervisor

cat >/etc/sudoers.d/liltweak-qualification <<EOF
Defaults!/opt/liltweak-qualification/libexec/supervisor env_reset,secure_path=/usr/sbin:/usr/bin:/sbin:/bin
liltweak-runner ALL=(root) NOPASSWD: /opt/liltweak-qualification/libexec/supervisor *
EOF
chown root:root /etc/sudoers.d/liltweak-qualification
chmod 0440 /etc/sudoers.d/liltweak-qualification
visudo -cf /etc/sudoers.d/liltweak-qualification >/dev/null

/opt/liltweak-qualification/libexec/supervisor configure \
  --runner-id galor-tweak-runner-01 \
  --repository-id github:islamismylifebey-web/lil-tweak

chmod 0555 /opt/liltweak-qualification/bin/collect /opt/liltweak-qualification/bin/destroy
chown root:root /opt/liltweak-qualification/bin/collect /opt/liltweak-qualification/bin/destroy
test "$(stat -c '%U:%G:%a:%h' /opt/liltweak-qualification/bin/collect)" = root:root:555:1
test "$(stat -c '%U:%G:%a:%h' /opt/liltweak-qualification/bin/destroy)" = root:root:555:1

echo "Qualification tooling installed. Use the emitted public variables for the GitHub environment."
