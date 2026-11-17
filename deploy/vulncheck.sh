#!/usr/bin/env bash
# Run govulncheck and fail on any finding not listed in deploy/govulncheck.allow.
# govulncheck has no ignore flag, and a finding with no fixed release would
# otherwise block every deploy. Each allowed ID needs a reason in that file.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

out="$(govulncheck ./... 2>&1)"
rc=$?
case $rc in
0) echo ">> govulncheck: no findings"; exit 0 ;;
3) ;; # findings; filter below
*) echo "$out" >&2; echo "govulncheck failed (exit $rc)" >&2; exit 1 ;;
esac

allowed="$(grep -oE '^GO-[0-9]+-[0-9]+' deploy/govulncheck.allow || true)"
found="$(grep -oE '^Vulnerability #[0-9]+: GO-[0-9]+-[0-9]+' <<<"$out" | awk '{print $3}' | sort -u)"
new="$(comm -23 <(echo "$found") <(echo "$allowed" | sort -u) | sed '/^$/d')"
if [[ -n "$new" ]]; then
	echo "$out" >&2
	echo "govulncheck: unallowed findings: ${new//$'\n'/ }" >&2
	exit 1
fi
echo ">> govulncheck: only allowed findings: ${found//$'\n'/ }"
