#!/usr/bin/env bash
# Gate, build, ship, back up, migrate, install, health-check.
# First-time server setup and rollback are in docs/deploy.md.
#
#   VOODOO_HOST=root@your-server make deploy
#
# VOODOO_HOST is required. VOODOO_SSH_KEY optionally names an identity file;
# without it ssh and scp use your normal SSH config and agent.
#
# The server-side steps (backup, migrate, install, health-check) are in
# deploy/install.sh, which this installs as /usr/local/sbin/voodoo-install.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${VOODOO_HOST:?set VOODOO_HOST=user@host}"
SSH_OPTS=()
# IdentitiesOnly: otherwise ssh offers agent keys first and the server can
# refuse with "too many authentication failures" before reaching this one.
if [[ -n "${VOODOO_SSH_KEY:-}" ]]; then SSH_OPTS=(-i "$VOODOO_SSH_KEY" -o IdentitiesOnly=yes); fi

echo ">> gate: clean tree"
if [[ -n "$(git status --porcelain)" ]]; then
	git status --short >&2
	echo "refusing to deploy a dirty tree; commit or stash first" >&2
	exit 1
fi
command -v govulncheck >/dev/null || { echo "govulncheck not found; run 'make tools'" >&2; exit 1; }

echo ">> gate: vet, test, govulncheck"
go vet ./...
go test ./...
./deploy/vulncheck.sh

rev="$(git rev-parse --short HEAD)"
echo ">> building static binary at $rev"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
	go build -ldflags="-s -w" -o bin/voodoo-linux-amd64 ./cmd/voodoo

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
cp bin/voodoo-linux-amd64 "$STAGE/voodoo"
cp deploy/backup.sh deploy/voodoo.service "$STAGE/"

echo ">> uploading installer and release to $HOST"
scp ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} deploy/install.sh "$HOST:/tmp/voodoo-install.new"
ssh ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "$HOST" 'install -m 0755 /tmp/voodoo-install.new /usr/local/sbin/voodoo-install && rm /tmp/voodoo-install.new'
tar -czf - -C "$STAGE" voodoo backup.sh voodoo.service |
	ssh ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "$HOST" sudo /usr/local/sbin/voodoo-install

echo ">> deployed $rev"
