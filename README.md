# kcal — kelliher calendar CLI

CLI for the [gluck-calendar](https://github.com/jack-work/gluck-calendar)
service, authenticated against [Authelia](https://auth.kelliher.info) via
OIDC's RFC 8628 device authorization flow. Refresh token stored in the
[hush](https://github.com/jack-work/hush) agent.

```
kcal login                                     # RFC 8628 device flow
kcal whoami
kcal ls [--from DATE] [--to DATE] [--json|--jsonl]
kcal add "Dentist" --at "2026-07-30 09:00" --loc "Peachtree Smiles" [--json]
kcal get <id> [--json]
kcal mv <id> --at "2026-07-30 10:00" --title "…" [--json]
kcal rm <id> [--json]
kcal share <id> <user> Read,Write,Delete,Share [--json]
kcal logout
kcal --version
```

## Machine-readable output

Follows [clig.dev](https://clig.dev/) conventions:

- **`--json`** (also `-j`) — emit JSON on stdout instead of the human table
  or labeled text. Works on every data-producing command:
  `ls`, `whoami`, `add`, `get`, `mv`, `rm`, `share`.
- **`--jsonl`** — emit [JSON Lines](https://jsonlines.org/) (one compact
  object per line). `ls` only. Streams cleanly through `jq -c`.
- Empty lists emit `[]`, never `null`.
- Errors and diagnostics go to **stderr**; data goes to **stdout**.
- Broken downstream pipes (`kcal ls --json | head`) exit silently, no
  stack trace.
- Exit codes: `0` success, `1` runtime error, `2` misuse (bad flags,
  missing args).

Example:

```bash
kcal ls --from 2026-07-01 --to 2026-07-31 --json | jq '.[] | select(.location=="Maple Street Guitar")'
kcal ls --jsonl | jq -c '{id, title, when: .dtstart}'
kcal get 15 --json | jq -r .location
```

## Auth model

1. `kcal login` → device flow against Authelia. Open the printed URL on
   any device with a browser, confirm the user code.
2. Access + refresh tokens land in hush (provider name `kcal`).
3. Every API call adds `Authorization: Bearer <jwt>`; Caddy's bearer
   bypass hands it to gluck-calendar, which validates the JWT against
   Authelia's JWKS.
4. On 401 the CLI asks hush to refresh once and retries; if the refresh
   token itself is rejected, run `kcal login` again.

## Configuration

| Env var           | Default                          |
|-------------------|----------------------------------|
| `KCAL_API`        | `https://cal.kelliher.info`      |
| `KCAL_ISSUER`     | `https://auth.kelliher.info`     |
| `KCAL_CLIENT_ID`  | `kcal`                           |
| `KCAL_HUSH_NAME`  | `kcal`                           |
| `KCAL_TOKEN`      | escape hatch: raw bearer token   |

## Date/time input

`--at` and `--end` accept RFC 3339 (`2026-07-30T09:00:00-04:00`) or the
looser `YYYY-MM-DD HH:MM` (interpreted in your local zone). Bare dates
roll to 00:00 local.

## Prerequisites

- `hush up -d` running.
- Membership in the `gluck-calendar-create` lldap group to create events.

## History

Formerly `gluck-calendar-cli` (binary `cal`). Renamed to `kcal` to start
retiring the `gluck-` prefix in favor of `k-` (kelliher).
