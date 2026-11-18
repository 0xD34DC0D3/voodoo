#!/usr/bin/env bash
# One-time: lets CI deploy as user "deploy", whose key can only run voodoo-install.
#
#   VOODOO_HOST=root@your-server deploy/ci-setup.sh path/to/ci_key.pub
set -euo pipefail

HOST="${VOODOO_HOST:?set VOODOO_HOST=user@host}"
SSH_OPTS=()
# IdentitiesOnly: otherwise ssh offers agent keys first and the server can
# refuse with "too many authentication failures" before reaching this one.
if [[ -n "${VOODOO_SSH_KEY:-}" ]]; then SSH_OPTS=(-i "$VOODOO_SSH_KEY" -o IdentitiesOnly=yes); fi
PUB="$(cat "${1:?usage: ci-setup.sh path/to/ci_key.pub}")"

ssh ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "$HOST" 'bash -s' <<REMOTE
set -euo pipefail
id deploy >/dev/null 2>&1 || useradd --system --create-home --shell /bin/sh deploy
install -d -m 0755 -o root -g root /home/deploy/.ssh
echo 'restrict,command="sudo -n /usr/local/sbin/voodoo-install" $PUB' > /home/deploy/.ssh/authorized_keys
chmod 0644 /home/deploy/.ssh/authorized_keys
echo 'deploy ALL=(root) NOPASSWD: /usr/local/sbin/voodoo-install' > /etc/sudoers.d/voodoo-deploy
chmod 0440 /etc/sudoers.d/voodoo-deploy
visudo -cf /etc/sudoers.d/voodoo-deploy
REMOTE
