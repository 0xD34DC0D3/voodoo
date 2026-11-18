# Deploying voodoo

This is the reference deployment: one Ubuntu VPS, voodoo under systemd, Caddy
in front for HTTPS. voodoo compiles to a single static binary (pure-Go SQLite,
templates and assets embedded), so a deploy ships one file. The only persistent
state is the SQLite database on local disk.

```
Internet ──▶ Caddy (:443, auto-HTTPS) ──▶ voodoo (127.0.0.1:8080, systemd) ──▶ /var/lib/voodoo/voodoo.db
```

Placeholders used throughout:

- `auth.example.com`: voodoo's public host. `example.com` is the parent domain
  your sibling apps live under.
- `<server-ip>`: the VPS's public IP.
- `root@your-server`: an SSH login with root (or passwordless sudo) on the VPS.
- `BUCKET_NAME`: the S3 bucket for off-box backups.

Anything else that runs Linux and systemd works too; the steps assume Ubuntu
24.04 LTS. A 1 vCPU / 1 GB instance is plenty.

## First-time server setup

Done once per server. After that, code deploys are `make deploy` (see
[Deploying new code](#deploying-new-code)).

1. **Point DNS.** Create an A (and, if you have IPv6, AAAA) record for
   `auth.example.com` pointing at `<server-ip>`. If your DNS provider can proxy
   traffic (Cloudflare's orange cloud, for example), turn that off for this
   record so Caddy can complete the Let's Encrypt challenge itself. Check that
   `dig +short auth.example.com` returns the server's IP.

2. **Create the service user and data directory:**
   ```sh
   adduser --system --group --no-create-home --home /var/lib/voodoo voodoo
   install -d -o voodoo -g voodoo /var/lib/voodoo
   ```

3. **Install the env file:**
   ```sh
   install -d /etc/voodoo
   # copy deploy/voodoo.env.example to /etc/voodoo/voodoo.env and edit it, then:
   chown root:voodoo /etc/voodoo/voodoo.env && chmod 0640 /etc/voodoo/voodoo.env
   ```
   At minimum set `VOODOO_BASE_URL` and `VOODOO_COOKIE_DOMAIN`. See
   [Configuration](#configuration).

4. **Install the systemd unit** (`deploy/voodoo.service` →
   `/etc/systemd/system/voodoo.service`):
   ```sh
   systemctl daemon-reload
   systemctl enable voodoo
   ```
   After this first copy, `make deploy` keeps the unit in sync.

5. **Install Caddy** and add voodoo's site block (`deploy/Caddyfile`) to
   `/etc/caddy/Caddyfile`. If the server already hosts other sites, add the
   block alongside theirs instead of replacing the file.
   ```sh
   apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
   curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
     | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
     > /etc/apt/sources.list.d/caddy-stable.list
   apt-get update && apt-get install -y caddy
   caddy validate --config /etc/caddy/Caddyfile
   systemctl reload caddy
   ```

6. **Firewall:** allow SSH, HTTP and HTTPS only.
   ```sh
   ufw allow OpenSSH && ufw allow 80,443/tcp && ufw --force enable
   ```

7. **Set up backups** (next section). `make deploy` takes a backup before
   every migration and refuses to continue if that fails. Off-box backups are
   optional (see [Local-only mode](#local-only-mode)), but `sqlite3` must be
   installed before the first deploy.

8. **First deploy** (build, ship the binary, run migrations), from your machine:
   ```sh
   VOODOO_HOST=root@your-server make deploy
   ```

9. **Create the first admin** (one-off, on the server):
   ```sh
   set -a; . /etc/voodoo/voodoo.env; set +a
   sudo -u voodoo --preserve-env=VOODOO_DB_PATH \
     /usr/local/bin/voodoo admin create-user --email you@example.com --admin
   ```
   It prompts for the password; there is no flag for it, so it never lands in
   `ps`, shell history or the sudo log. Log in at `https://auth.example.com`
   and invite everyone else from `/admin/invites`.

10. **Test a restore** ([Restoring from backup](#restoring-from-backup)) once
    after setup, and again after any change to the backup script.

## Backups

`deploy/backup.sh` is installed as `/usr/local/bin/voodoo-backup` by
`make deploy` and runs nightly from root's cron. Each run:

1. copies the live database with `sqlite3 .backup`;
2. runs `PRAGMA integrity_check` on the copy and fails if it is not `ok`;
3. keeps a gzip in `/var/backups/voodoo` (root-only, `0700`/`0600`), pruned
   after 14 days (`VOODOO_BACKUP_KEEP_DAYS`);
4. if off-box backup is configured, encrypts the gzip with
   [age](https://age-encryption.org) to a public key and uploads it to S3;
5. optionally pings a dead-man's-switch URL on success and `<url>/fail` on
   error (any service that accepts those pings, such as healthchecks.io).

The server only holds the age public key, and the IAM credentials can only
write new objects, so a compromised server can neither read nor delete
existing off-box backups. Alerting on missed or failed backups is up to you:
without `VOODOO_BACKUP_HEALTHCHECK_URL`, a silently failing cron job goes
unnoticed.

### Local-only mode

With none of `VOODOO_BACKUP_S3_URI`, `VOODOO_BACKUP_AGE_RECIPIENT`,
`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` set (or no
`/etc/voodoo/backup.env` at all), the script does steps 1 to 3 and 5, prints a
`WARNING: off-box backup not configured` line, and exits 0. `age` and `aws`
are not needed. This is supported but not recommended for production: every
copy lives on the same disk as the database, so losing the server loses the
backups too. Setting some but not all of those four variables is treated as a
misconfiguration and fails the run (and therefore `make deploy`).

### Off-box setup

One-time setup:

1. **Encryption key, on your machine, not the server:**
   ```sh
   age-keygen -o voodoo-backup.key   # prints the public key: age1...
   ```
   Store `voodoo-backup.key` somewhere safe, in at least two places (a
   password manager, for example). It is the only way to restore an off-box
   backup.

2. **S3 bucket:** private (block public access on), versioning on, lifecycle
   from `deploy/aws/backup-lifecycle.json`:
   ```sh
   aws s3api create-bucket --bucket BUCKET_NAME
   aws s3api put-bucket-versioning --bucket BUCKET_NAME \
     --versioning-configuration Status=Enabled
   aws s3api put-bucket-lifecycle-configuration --bucket BUCKET_NAME \
     --lifecycle-configuration file://deploy/aws/backup-lifecycle.json
   ```
   Outside `us-east-1`, add `--create-bucket-configuration LocationConstraint=REGION`.

3. **IAM user** with only `deploy/aws/backup-iam-policy.json` attached
   (`s3:PutObject` on `BUCKET_NAME/voodoo/*`; edit the bucket name in the
   policy first). Create an access key for it.

4. **Optional healthcheck:** create a check with a 1-day period and a few
   hours' grace in a monitoring service of your choice and note its ping URL.

5. **On the server** (local-only mode needs just `sqlite3` and the cron line):
   ```sh
   apt-get install -y sqlite3 age
   snap install aws-cli --classic
   install -m 0600 -o root -g root /dev/null /etc/voodoo/backup.env
   # fill in from deploy/backup.env.example
   ```
   and add to root's crontab (`crontab -e`):
   ```
   15 4 * * * /usr/local/bin/voodoo-backup
   ```
   The script is not on the server until the first `make deploy`. To test
   before then, copy `deploy/backup.sh` to `/usr/local/bin/voodoo-backup`
   (mode `0755`) by hand, run it once, and confirm the object lands in S3.

## Deploying new code

From your machine, on a clean checkout:

```sh
make tools                                   # once: pinned sqlc, goose, govulncheck
VOODOO_HOST=root@your-server make deploy
```

`VOODOO_HOST` is required. Set `VOODOO_SSH_KEY=/path/to/key` to use a specific
identity file; otherwise `ssh` and `scp` use your normal SSH config and agent.

Locally, `make deploy` refuses a dirty git tree (untracked files included), then
runs `go vet`, `go test` and `deploy/vulncheck.sh` (`govulncheck` with the
allowlist in `deploy/govulncheck.allow`). Any failure stops the deploy before
anything is uploaded. It then cross-compiles a static `linux/amd64` binary and
uploads it with two repo files:

| Repo file               | Server path                          | Mode |
| ----------------------- | ------------------------------------ | ---- |
| built binary            | `/usr/local/bin/voodoo`              | 0755 |
| `deploy/backup.sh`      | `/usr/local/bin/voodoo-backup`       | 0755 |
| `deploy/voodoo.service` | `/etc/systemd/system/voodoo.service` | 0644 |
| `deploy/install.sh`     | `/usr/local/sbin/voodoo-install`     | 0755 |

Edit those files in the repo, never on the server; `make deploy` overwrites
the server copies.

On the server, in order:

1. Installs the backup script and runs it. If the backup fails, the deploy
   stops with nothing changed. Without off-box config the backup is local-only
   and warns; a partially filled `/etc/voodoo/backup.env` fails it.
2. Installs the unit file and runs `systemctl daemon-reload`, only if the unit
   changed.
3. Stops the service. voodoo is down from here until step 6, usually a few
   seconds. Stopping avoids a running old binary seeing a migrated schema.
4. Runs `migrate up` with the new binary as the `voodoo` user. If it fails,
   the old binary is restarted and the deploy stops.
5. Copies the old binary to `/usr/local/bin/voodoo.prev` and installs the new one.
6. Starts the service and polls `GET /healthz` on the local listen address
   (`VOODOO_BIND`/`VOODOO_PORT`). If it does not answer `ok` within about ten
   seconds, the deploy fails and prints the rollback command; the service's
   log stays on the server (`journalctl -u voodoo`).

### Rolling back

The previous binary is kept as `/usr/local/bin/voodoo.prev`. On the server:

```sh
install -m 0755 /usr/local/bin/voodoo.prev /usr/local/bin/voodoo
systemctl restart voodoo
curl -fsS http://127.0.0.1:8080/healthz
```

Only one previous binary is kept; the next deploy overwrites it.

Migrations are not reversed. That is fine when the old binary still works
against the new schema (additive migrations). When it does not, also restore
the backup taken at the start of the deploy: it is the newest file in
`/var/backups/voodoo`. Follow [Restoring from backup](#restoring-from-backup),
but skip its `migrate up` step, which would re-apply the migration. Anything
written between the backup and the rollback is lost.

### The Caddyfile is not deployed

`make deploy` never touches `/etc/caddy/Caddyfile`, because that file may also
serve other sites. Apply Caddy changes by hand:

```sh
cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak
# edit the auth.example.com block to match deploy/Caddyfile
caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy
```

Reload, never restart. A failed reload leaves the running config serving, so the
worst case is "the change didn't apply". A restart re-reads from disk, so a
broken file takes down every site on the box until someone fixes it.

### Deploying from CI

Every push to `main` that passes the `test` job deploys through the `deploy`
job in `.github/workflows/ci.yml`. CI never gets root:

- It connects as user `deploy`. That user's key is `restrict`ed and forced to
  run `sudo /usr/local/sbin/voodoo-install`, which only reads a release
  tarball on stdin. No shell, no forwarding, no other command.
- `voodoo-install` is installed only by `make deploy` (root), so CI can't
  replace it.
- The job runs in the `production` GitHub environment, which only `main` may
  use (set up below). Pull requests, including those from forks, never see its
  secrets.
- The server's host key is pinned, and the actions are pinned to commit SHAs.
- The workflow grants no token permissions beyond `contents: read`, checkouts
  do not keep the token, and each job times out after 20 minutes.

One-time setup (run `make deploy` once first so `voodoo-install` exists):

```sh
# A throwaway directory, so the private key never sits in the checkout.
keydir="$(mktemp -d)"
ssh-keygen -t ed25519 -N "" -C voodoo-ci -f "$keydir/ci_key"
VOODOO_HOST=root@your-server deploy/ci-setup.sh "$keydir/ci_key.pub"
gh secret set DEPLOY_SSH_KEY --env production < "$keydir/ci_key"
gh secret set DEPLOY_HOST --env production --body deploy@your-server
gh secret set DEPLOY_KNOWN_HOSTS --env production --body "$(ssh-keyscan -t ed25519 your-server 2>/dev/null | grep -v '^#')"
gh variable set DEPLOY_ENABLED --body true
rm -rf "$keydir"
```

Then let only `main` use the `production` environment. Without this, anyone
with write access could push a branch whose own `ci.yml` runs a job in
`production` and reads its secrets, SSH key included; with it, only `main` can
(replace OWNER/REPO):

```sh
gh api -X PUT repos/OWNER/REPO/environments/production --input - <<'EOF'
{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
EOF
gh api -X POST repos/OWNER/REPO/environments/production/deployment-branch-policies -f name=main -f type=branch
```

Also protect `main` (require pull requests, block force pushes), so getting
code onto it takes more than write access.

Revoke CI by deleting `/home/deploy/.ssh/authorized_keys` on the server.

#### Keeping the public log clean

The repository is public, so its Actions logs are too. The deploy keeps the
SSH user and port, sshd's banner, production logs (journal output), the
backup bucket's name and the healthcheck URL out of them. It does not hide the
server's IP: the DNS A record for `auth.example.com` makes that public
anyway, so masking it is only defence in depth.

- `DEPLOY_HOST` and `DEPLOY_KNOWN_HOSTS` are environment secrets, not
  variables: GitHub prints a step's env block in the log, and variables are
  shown in clear. Whole-secret masking misses the bare host that `ssh` errors
  print and individual lines of a multi-line secret, so the deploy step also
  `::add-mask::`s the host, the host after `@`, each known_hosts line and each
  host name in it.
- A job-level `if` cannot read secrets (or environment variables), so the job
  is gated on the repository variable `DEPLOY_ENABLED` being `true` instead.
  Unset, the deploy job is skipped.
- On the server, `install.sh` sends a failed `migrate up`'s output to the
  journal (`journalctl -t voodoo-install`) and answers a failed health check
  with a pointer to `journalctl -u voodoo` instead of `systemctl status`.
  `backup.sh` runs `age`, `aws s3 cp` and the healthcheck `curl` through
  `quiet`, which logs their stderr to the journal
  (`journalctl -t voodoo-backup`) and prints a generic line. Exit codes are
  unchanged, and so is what a successful deploy prints.

**Migrating an existing setup** (from `DEPLOY_HOST` and `DEPLOY_KNOWN_HOSTS`
as `production` environment variables): before pushing this change to `main`,
create the two environment secrets and the `DEPLOY_ENABLED` repository
variable (the SSH key stays):

```sh
gh secret set DEPLOY_HOST --env production --body deploy@your-server
gh secret set DEPLOY_KNOWN_HOSTS --env production --body "$(ssh-keyscan -t ed25519 your-server 2>/dev/null | grep -v '^#')"
gh variable set DEPLOY_ENABLED --body true
```

After the push has deployed, delete the old environment variables, which
nothing reads any more:

```sh
gh variable delete DEPLOY_HOST --env production
gh variable delete DEPLOY_KNOWN_HOSTS --env production
```

## Configuration

Every environment variable is listed in `deploy/voodoo.env.example` (production)
and `.env.example` (local development); [docs/auth.md](auth.md) describes each.
Worth calling out:

- `VOODOO_BASE_URL`: voodoo's public URL, e.g. `https://auth.example.com`.
- `VOODOO_SITE_URL`: the deadcode website, e.g. `https://example.com`.
- `VOODOO_COOKIE_DOMAIN`: the parent domain with a leading dot
  (`.example.com`) to share the session cookie with sibling apps. voodoo refuses
  to start with a cookie domain unless `VOODOO_COOKIE_SECURE=true`.
- `VOODOO_BIND`: listen address, default `127.0.0.1`. Caddy is the only
  intended client and voodoo terminates no TLS of its own. Set it to the empty
  string to bind all interfaces (only useful if the proxy is on another host).
- `VOODOO_PORT`: default `8080`. Must match the `reverse_proxy` upstream in the
  Caddyfile.

## Operating

- Logs: `journalctl -u voodoo -f`
- Restart: `systemctl restart voodoo`
- Caddy logs and certificate status: `journalctl -u caddy -f`
- Health check: `curl https://auth.example.com/healthz`
- Users from the CLI: `voodoo admin list`, `voodoo admin promote <email>`,
  `voodoo admin demote <email>` (run as the `voodoo` user with
  `VOODOO_DB_PATH` set, as in setup step 9).

## Restoring from backup

The local copies in `/var/backups/voodoo` are fastest. Use S3 when the server
or its disk is gone.

1. **Get the file.** From S3, on a machine with read access to the bucket and
   the age private key:
   ```sh
   aws s3 ls s3://BUCKET_NAME/voodoo/            # pick the newest
   aws s3 cp s3://BUCKET_NAME/voodoo/voodoo-STAMP.db.gz.age .
   age -d -i voodoo-backup.key voodoo-STAMP.db.gz.age | gunzip > voodoo.db
   ```
   From the local copies: `gunzip -c /var/backups/voodoo/voodoo-STAMP.db.gz > voodoo.db`.

2. **Check it:** `sqlite3 voodoo.db 'PRAGMA integrity_check;'` must print `ok`.

3. **Swap it in** on the server:
   ```sh
   systemctl stop voodoo
   mv /var/lib/voodoo/voodoo.db /var/lib/voodoo/voodoo.db.broken
   rm -f /var/lib/voodoo/voodoo.db-wal /var/lib/voodoo/voodoo.db-shm
   install -m 0600 -o voodoo -g voodoo voodoo.db /var/lib/voodoo/voodoo.db
   sudo -u voodoo env VOODOO_DB_PATH=/var/lib/voodoo/voodoo.db \
     /usr/local/bin/voodoo migrate up
   systemctl start voodoo
   ```
   Then log in and confirm. Delete `voodoo.db.broken` once satisfied, and
   shred any plaintext `voodoo.db` left on your own machine.

Anything written after the backup's timestamp is lost: new users, keys,
sessions and OAuth grants since then. Users may need to log in again.
