# Contributing

Issues and pull requests are welcome. For anything larger than a small fix,
open an issue first so we can agree on the approach; voodoo deliberately stays
small (see the non-goals in the [README](README.md)).

## Setup

- Go version from `go.mod`.
- `make tools` installs the pinned `sqlc`, `goose` and `govulncheck`.
- `make help` lists every target.

## Before sending a change

```sh
gofmt -l .        # must print nothing
make vet
make test         # CI also runs go test -race ./...
make vulncheck
```

CI runs the same checks and fails if generated sqlc code is out of date.

## Database changes

- Schema lives in goose migrations under `migrations/`, embedded in the binary.
  Add one with `make migrate-new NAME=add_thing`; never edit a migration that
  has been released. Write a working `-- +goose Down` section.
- Queries live in `internal/auth/store/queries.sql`. After changing a query or
  a migration, run `make sqlc` and commit the regenerated files in
  `internal/auth/store/`. Do not edit the generated `queries.sql.go`, `db.go` or
  `models.go` by hand.
- `queries.sql` must be ASCII-only, comments included: sqlc's SQLite parser
  mixes rune and byte offsets and mis-splices queries after any multi-byte
  character. `make sqlc` checks this. See the comment in `sqlc.yaml`.

## Style

- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(auth): ...`, `fix(deploy): ...`, `docs: ...`), short and imperative.
- Keep pages working without JavaScript; the CSP forbids inline script.
- Update `docs/` when you change routes, configuration or behaviour.

By contributing you agree that your contributions are licensed under the
project's [MIT license](LICENSE).
