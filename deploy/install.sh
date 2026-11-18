#!/usr/bin/env bash
# Runs on the server as root. Reads a tar.gz of voodoo, backup.sh and
# voodoo.service on stdin; it is the only command the CI deploy key may run.
set -euo pipefail
BIN=/usr/local/bin/voodoo
ROLLBACK="install -m 0755 $BIN.prev $BIN && systemctl restart voodoo"

# CI pipes this script's output into a public Actions log, so failure detail
# that can name hosts, addresses or paths goes to the journal (tag
# voodoo-install) and the log only says where to look.
journal() { logger -t voodoo-install -p user.err -- "$1" 2>/dev/null || true; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf - -C "$work" --no-same-owner --no-same-permissions voodoo backup.sh voodoo.service

install -m 0755 "$work/backup.sh" /usr/local/bin/voodoo-backup
install -m 0755 "$work/voodoo" "$BIN.new"

echo ">> pre-migration backup"
if ! /usr/local/bin/voodoo-backup; then
	rm -f "$BIN.new"
	echo "!! backup failed; nothing changed, service untouched" >&2
	exit 1
fi

# daemon-reload only when the unit changed (cmp also fails on first install,
# which is what we want).
if ! cmp -s "$work/voodoo.service" /etc/systemd/system/voodoo.service; then
	echo ">> unit changed; installing and reloading systemd"
	install -m 0644 "$work/voodoo.service" /etc/systemd/system/voodoo.service
	systemctl daemon-reload
fi

# NOT automated: /etc/caddy/Caddyfile. It may hold other sites' blocks, so
# neither copying nor appending is safe. Apply Caddy changes by hand.

set -a; . /etc/voodoo/voodoo.env; set +a

echo ">> stopping service"
systemctl stop voodoo

# voodoo has no doctor; migrate is the only preflight. Its errors carry
# database detail, so on failure they go to the journal.
echo ">> migrating with the new binary"
if ! migrate_out="$(sudo -u voodoo --preserve-env=VOODOO_DB_PATH "$BIN.new" migrate up 2>&1)"; then
	journal "migrate up failed: $migrate_out"
	rm -f "$BIN.new"
	systemctl start voodoo
	echo "!! migration failed; old binary restarted. Details: run" >&2
	echo "!! 'journalctl -t voodoo-install' on the server. If the schema is now" >&2
	echo "!! inconsistent, restore the backup above (docs/deploy.md)." >&2
	exit 1
fi
printf '%s\n' "$migrate_out"

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
# The service's own log is production data; it stays on the server.
echo "!! health check failed; run 'journalctl -u voodoo' on the server." >&2
echo "!! Roll back the binary with:" >&2
echo "!!   $ROLLBACK" >&2
echo "!! Migrations are not reversed; see docs/deploy.md for restoring the backup." >&2
exit 1
