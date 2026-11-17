#!/usr/bin/env bash
# Gate, build, ship, back up, migrate, install, health-check.
# First-time server setup and rollback are in docs/deploy.md.
#
#   VOODOO_HOST=root@your-server make deploy
#
# VOODOO_HOST is required. VOODOO_SSH_KEY optionally names an identity file;
# without it ssh and scp use your normal SSH config and agent.
#
# Order on the server, with the service stopped for the whole window:
#   1. pre-migration backup (voodoo-backup); abort if it fails
#   2. stop the service
#   3. migrate with the NEW binary; on failure restart the old one and abort
#   4. keep the old binary as voodoo.prev, install the new one
#   5. start, then health-check /healthz; on failure print the rollback command
#
# Also ships deploy/backup.sh and deploy/voodoo.service so the server copies
# cannot drift from the repo. The Caddyfile is deliberately not shipped; see
# docs/deploy.md.
set -euo pipefail
cd "$(dirname "$0")/.."

HOST="${VOODOO_HOST:?set VOODOO_HOST=user@host}"
SSH_OPTS=()
if [[ -n "${VOODOO_SSH_KEY:-}" ]]; then SSH_OPTS=(-i "$VOODOO_SSH_KEY"); fi

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

echo ">> uploading to $HOST"
scp ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} bin/voodoo-linux-amd64 "$HOST:/tmp/voodoo.new"
scp ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} deploy/backup.sh "$HOST:/tmp/voodoo-backup.new"
scp ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} deploy/voodoo.service "$HOST:/tmp/voodoo.service.new"

ssh ${SSH_OPTS[@]+"${SSH_OPTS[@]}"} "$HOST" 'bash -s' <<'REMOTE'
set -euo pipefail
BIN=/usr/local/bin/voodoo
ROLLBACK="install -m 0755 $BIN.prev $BIN && systemctl restart voodoo"

install -m 0755 /tmp/voodoo-backup.new /usr/local/bin/voodoo-backup
install -m 0755 /tmp/voodoo.new "$BIN.new"
rm -f /tmp/voodoo.new /tmp/voodoo-backup.new

echo ">> pre-migration backup"
if ! /usr/local/bin/voodoo-backup; then
	rm -f "$BIN.new" /tmp/voodoo.service.new
	echo "!! backup failed; nothing changed, service untouched" >&2
	exit 1
fi

# daemon-reload only when the unit changed (cmp also fails on first install,
# which is what we want).
if ! cmp -s /tmp/voodoo.service.new /etc/systemd/system/voodoo.service; then
	echo ">> unit changed; installing and reloading systemd"
	install -m 0644 /tmp/voodoo.service.new /etc/systemd/system/voodoo.service
	systemctl daemon-reload
fi
rm -f /tmp/voodoo.service.new

# NOT automated: /etc/caddy/Caddyfile. It may hold other sites' blocks, so
# neither copying nor appending is safe. Apply Caddy changes by hand.

set -a; . /etc/voodoo/voodoo.env; set +a

echo ">> stopping service"
systemctl stop voodoo

echo ">> migrating with the new binary"
if ! sudo -u voodoo --preserve-env=VOODOO_DB_PATH "$BIN.new" migrate up; then
	rm -f "$BIN.new"
	systemctl start voodoo
	echo "!! migration failed; old binary restarted. If the schema is now" >&2
	echo "!! inconsistent, restore the backup above (docs/deploy.md)." >&2
	exit 1
fi

echo ">> installing (previous binary kept as $BIN.prev)"
if [[ -f "$BIN" ]]; then cp -p "$BIN" "$BIN.prev"; fi
mv "$BIN.new" "$BIN"
systemctl start voodoo

addr="${VOODOO_BIND:-127.0.0.1}"
[[ -n "$addr" && "$addr" != "0.0.0.0" && "$addr" != "::" ]] || addr=127.0.0.1
[[ "$addr" == *:* ]] && addr="[$addr]"
url="http://$addr:${VOODOO_PORT:-8080}/healthz"

echo ">> health check $url"
for _ in $(seq 10); do
	if [[ "$(curl -fsS -m 3 "$url" 2>/dev/null)" == "ok" ]]; then
		echo ">> healthy"
		exit 0
	fi
	sleep 1
done
systemctl --no-pager --lines=20 status voodoo || true
echo "!! health check failed. Roll back the binary with:" >&2
echo "!!   $ROLLBACK" >&2
echo "!! Migrations are not reversed; see docs/deploy.md for restoring the backup." >&2
exit 1
REMOTE

echo ">> deployed $rev"
