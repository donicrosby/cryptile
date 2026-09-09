# cryptile live integration harness

Boots a real Vaultwarden server (pinned `1.37.2`), provisions a service
account + org `hermes` + collection `shared` + seeded ciphers entirely
through the public Bitwarden-compatible API, then runs the real `cryptile`
binary against it. Complements the wiremock suites: those prove wire shape,
this proves current-VW behavior end to end.

## Run

    ./integration/run_live_tests.sh

Exit code = number of failed assertions (0 = all green). Output is safe to
paste: assertions compare values without echoing secrets.

Requirements: docker (compose v2 plugin or standalone), python3 with
`cryptography`, curl, a rust toolchain (builds the debug binary).

## What it proves

- `login` against a live VW: prelogin → KDF → register-published params →
  token grant → session sealed in the keyring
- `get vw:shared/Postgres HQ:password` returns the exact plaintext the
  harness sealed at provision time (independent Python crypto cross-checking
  the Rust implementation)
- `list vw:shared` metadata-only, no plaintext leak
- `export --format env|json` with mangled keys (`POSTGRES_HQ_PASSWORD`)
- wrong keyring passphrase → nonzero exit, no leak
- missing item → exit 5 not-found
- the `--passphrase-env` non-TTY path works against a live server

## Manual poking

    docker compose -p cryptile-vw -f integration/docker-compose.yml up -d
    # web vault: http://127.0.0.1:8222 (svc-hermes@live.test /
    #   harness-master-password after a run — inspect summary in
    #   integration/.run/provision-summary.json)
    docker compose -p cryptile-vw -f integration/docker-compose.yml down -v

Containerized runners (CI-in-docker, agent sandboxes on a docker bridge)
can't reach the host's 127.0.0.1; set `CRYPTILE_VW_BIND=0.0.0.0` and point
`CRYPTILE_LIVE_BASE` at the bridge gateway
(`http://172.17.0.1:8222`) instead.

## Failure modes

- `vaultwarden never became healthy` — image pull slow / port clash; retry,
  or check `docker logs cryptile-vw`
- `provision failed` — API bootstrap broke; the printed HTTP error names the
  failing hop (register / token / organizations / ciphers)
- value mismatches — Rust vs Python crypto disagreement; that's the signal
  the cross-check exists for, not a harness bug

## Files

- `docker-compose.yml` — the stack (loopback-bound, named volume)
- `provision.py` — API bootstrap with independent Python crypto (whitepaper
  + rbw/goldwarden-verified protocol; no VW implementation code)
- `run_live_tests.sh` — orchestrator + assertions
- `.run/` — scratch (state dir, provision summary); gitignored
