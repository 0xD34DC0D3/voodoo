#!/usr/bin/env bash
# Nightly SQLite backup, run from root's cron.
#
# 1. Online copy via sqlite3 ".backup" (safe against the live database).
# 2. PRAGMA integrity_check on the copy; a corrupt copy fails the run.
# 3. Local gzip copy in $DEST, pruned after $KEEP_DAYS days (fast restore).
# 4. Off-box copy: gzip, encrypt with age to a public key, upload to S3.
#    The server holds only the public key, and the IAM user can only
#    PutObject, so a compromised server can neither read nor delete backups.
#    Optional: with none of the off-box settings present, the run is
#    local-only and prints a warning. With some but not all, it fails.
# 5. Optionally ping a healthcheck URL (e.g. healthchecks.io) on success and
#    <url>/fail on any error. A missing ping is the alert.
#
# Config: /etc/voodoo/backup.env (root:root 0600). See docs/deploy.md.
set -euo pipefail

# Each dump is a full copy of the auth database. The umask must be set before
# anything is created: sqlite3 ".backup" and gzip both honour it, and the cron
# default of 0022 would leave every dump 0644. (The systemd unit sets
# UMask=0077, but cron does not inherit that.)
umask 077

CONF=/etc/voodoo/backup.env
if [[ -f "$CONF" ]]; then
  # shellcheck disable=SC1090
  source "$CONF"
fi

DB="${VOODOO_DB_PATH:-/var/lib/voodoo/voodoo.db}"
DEST="${VOODOO_BACKUP_DIR:-/var/backups/voodoo}"
KEEP_DAYS="${VOODOO_BACKUP_KEEP_DAYS:-14}"

# Off-box upload is all-or-nothing: none set means local-only (supported, not
# recommended), a partial set is a misconfiguration and fails the run.
OFFBOX_VARS=(VOODOO_BACKUP_S3_URI VOODOO_BACKUP_AGE_RECIPIENT AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY)
set_vars=() missing=()
for v in "${OFFBOX_VARS[@]}"; do
  if [[ -n "${!v:-}" ]]; then set_vars+=("$v"); else missing+=("$v"); fi
done
if (( ${#set_vars[@]} == 0 )); then
  OFFBOX=0
elif (( ${#missing[@]} == 0 )); then
  OFFBOX=1
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
else
  echo "off-box backup partially configured in $CONF; missing: ${missing[*]}" >&2
  exit 1
fi
HC_URL="${VOODOO_BACKUP_HEALTHCHECK_URL:-}"

# The deploy runs this with its output in a public CI log, and age, aws and
# curl errors can name the bucket, key or healthcheck URL. quiet runs a
# command, sends its stderr to the journal (journalctl -t voodoo-backup) on
# failure, prints only a generic line, and keeps the command's exit status.
quiet() {
  local what="$1" errf rc=0
  shift
  errf="$(mktemp)"
  "$@" 2>"$errf" || rc=$?
  if (( rc != 0 )); then
    logger -t voodoo-backup -p user.err -- "$what failed (exit $rc): $(head -c 4000 "$errf")" 2>/dev/null || true
    echo "$what failed; details: journalctl -t voodoo-backup on the server" >&2
  fi
  rm -f "$errf"
  return "$rc"
}

ping_hc() {
  [[ -n "$HC_URL" ]] || return 0
  quiet "healthcheck ping" curl -fsS -m 10 --retry 3 -o /dev/null "$HC_URL$1" || true
}
trap 'ping_hc /fail' ERR

# Fresh server: the first deploy runs this before any migration has created
# the database. Opening a missing file with sqlite3 would create it, owned by
# root, and the voodoo user could then not migrate it.
if [[ ! -f "$DB" ]]; then
  echo "no database at $DB yet; nothing to back up"
  exit 0
fi

# install -d re-applies the mode on every run; mkdir -p is a no-op on an
# existing directory. root:root 0700 on purpose: root's cron is the only
# reader, and the voodoo service account should not be able to read 14 days
# of database copies if it is ever compromised.
install -d -m 0700 "$DEST"

stamp="$(date -u +%Y%m%d-%H%M%S)"
out="$DEST/voodoo-$stamp.db"

sqlite3 "$DB" ".backup '$out'"

check="$(sqlite3 "$out" 'PRAGMA integrity_check;')"
if [[ "$check" != "ok" ]]; then
  echo "integrity_check failed on $out: $check" >&2
  false
fi

gzip -f "$out"  # .gz inherits the 0600 of its input

if (( OFFBOX )); then
  enc="$out.gz.age"
  quiet "age encrypt" age -r "$VOODOO_BACKUP_AGE_RECIPIENT" -o "$enc" "$out.gz"
  quiet "off-box upload" aws s3 cp --only-show-errors "$enc" "${VOODOO_BACKUP_S3_URI%/}/$(basename "$enc")"
  rm -f "$enc"
else
  echo "WARNING: off-box backup not configured (see $CONF); local copy only at $out.gz" >&2
fi

find "$DEST" -name 'voodoo-*.db.gz' -mtime "+$KEEP_DAYS" -delete

ping_hc ""
