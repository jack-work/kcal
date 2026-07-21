# kcal — kelliher calendar CLI

CLI for the [gluck-calendar](https://github.com/jack-work/gluck-calendar)
service, authenticated against [Authelia](https://auth.kelliher.info) via
OIDC's RFC 8628 device authorization flow. Refresh token stored in the
[hush](https://github.com/jack-work/hush) agent.

```
kcal login                                     # RFC 8628 device flow
kcal whoami
kcal ls [--from DATE] [--to DATE]
kcal add "Dentist" --at "2026-07-30 09:00" --loc "Peachtree Smiles"
kcal get <id>
kcal mv <id> --at "2026-07-30 10:00" --title "…"
kcal rm <id>
kcal share <id> <user> Read,Write,Delete,Share
kcal logout
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
