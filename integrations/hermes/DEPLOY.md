# Deploying the cryptile plugin into a Hermes image

No custom image needed. Two artifacts land on the **persistent volume**
(`/opt/data` in the Nous cloud deployment — the directory that already
survives `update-hermes-agent.sh --apply` and carries `plugins/even-g2`,
`plugins/hermes-lcm`, `bin/tirith`), plus one line in `~/.hermes/.env`:

```
/opt/data/plugins/cryptile/{plugin.yaml,__init__.py}   # directory plugin
/opt/data/bin/cryptile                                 # static musl binary
CRYPTILE_PASSPHRASE=…                                  # in ~/.hermes/.env
```

Hermes discovers `~/.hermes/plugins/` — for this deployment the home dir
*is* on the persistent volume, so the plugin rides updates untouched.
`get_hermes_home()` is a real API (`hermes_constants`), not a hack:
directory-plugin + `HERMES_BUNDLED_PLUGINS` env override are the two
first-class extension points.

## Build the static binary (any glibc/musl mismatch killed)

```sh
rustup target add x86_64-unknown-linux-musl
apt-get install -y musl-tools   # or brew FiloSottile/musl-cross
cargo build --release --target x86_64-unknown-linux-musl
install -m 755 target/x86_64-unknown-musl/release/cryptile /opt/data/bin/
```

Static-pie, zero runtime deps. The plugin's `_find_binary` resolves
`/opt/data/bin/cryptile` via PATH (`/home/hermes/.local/bin` etc.) or pin
it: `secrets.cryptile.binary_path: /opt/data/bin/cryptile`.

## Update flow

`update-hermes-agent.sh --apply` replaces only the image; volume contents
persist. To bump cryptile itself: rebuild musl binary → `install` over
`/opt/data/bin/cryptile` → restart Hermes. The plugin files only change
when `integrations/hermes/` changes (copy them again).

## Alternatives considered

- **Upstream PR to NousResearch/hermes-agent `plugins/`** — the *right*
  long-term answer: `plugins = ["**/plugin.yaml"]` package-data already
  ships manifests in wheels, so cryptile ships with every Hermes install.
  MIT vs Apache-2.0 dual-licensing would need sorting. Blocked on repo
  ownership (not our repo to push into).
- **`pip install cryptile-plugin` entry-point plugin** — the
  `hermes_agent.plugins` entry-point group exists, but a Rust binary still
  needs shipping; entry-points solve Python-side distribution only.
- **Custom image** — unnecessary; the volume-plugin mechanism is the
  intended extension surface.
