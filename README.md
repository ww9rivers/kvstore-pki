# kvstore-pki: Tool to Setup SSL for Splunk KV-Store Connection with MongoDB

A python based tool to create a self-signed TLS certificate for the Splunk server (`splunkd`) to communicate
to the KV store service (`mongod`) with `X509v3 Extended Key Usage` attributes for both `clientAuth` and `serverAuth`.
The certificate need to certify the host's hostname in FQDN format, its IP address, as well as `localhost` and the
loopback IP.

The tool also configures Splunk server to use the created CA cert, private key and server certificate so that
`splunkd` and `mongod` communicate properly.

The KV store certificate is scoped to `[kvstore]` only. The third-party (InCommon) certificate stays on Splunk Web
(8000) and the management port (8089). See [docs/PLAN.md](docs/PLAN.md) for the design.

## Install

Requires Python 3.9+ and `cryptography>=40`.

```shell
pip install .            # or: pip install -e '.[dev]' for tests
```

Or run it straight from a checkout with no install, via `bin/kvstore-pki`. It picks
`.venv/bin/python3` if present (e.g. `python3 -m venv --system-site-packages .venv && .venv/bin/pip install cryptography`),
else `$KVSTORE_PKI_PYTHON`, else `python3` on `PATH`:

```shell
./bin/kvstore-pki check
```

## Usage

Run as root (files are chowned to `--owner`, default `splunk`) or as the `splunk` user.

```shell
kvstore-pki check                                   # read-only diagnosis; changes nothing
kvstore-pki --dry-run setup                         # show what would be written and the server.conf diff
kvstore-pki setup                                   # issue + trust + configure, no restart
sudo systemctl restart Splunkd
kvstore-pki verify --auth admin:<password>          # after the restart
```

`setup --restart` also restarts the `Splunkd` unit (`--service` to change it), waits for the KV store port, and
runs `verify`.

| Command | What it does |
| --- | --- |
| `check` | Reports the version marker (`versionFile42`), `kvstoreUpgradeOnStartupEnabled`, the resolved KV store cert (key present, key match, EKU, expiry), partial TLS settings in `[kvstore]`, the `-x509_strict` chain, and whether mongod is up. It reports only and fixes nothing. |
| `issue` | Creates or reuses the local CA and issues the dual-EKU leaf. It builds `kvstore-server.pem`, then verifies the result both in Python and with `splunk cmd openssl`. |
| `trust` | Rebuilds `ca-combined.pem`: the current `[sslConfig]/sslRootCAPath` bundle plus the local CA. The source file is never modified. |
| `configure` | Backs up `etc/system/local/server.conf`. It sets `[kvstore] disabled`/`serverCert` and `[sslConfig] sslRootCAPath`, and comments out deprecated `[kvstore]` TLS keys. Afterwards it confirms the result with btool. |
| `verify` | Checks after a restart: `splunkd.log`, `mongod.log`, port 8191, the cert served on 8191, and `kvstore-status`. It also confirms 8089 and 8000 still present the third-party issuer. |
| `expiry` | Prints the CA and leaf expiry dates. It exits 1 if either expires within `--warn-days` (default 30). |

Useful options for `issue`/`setup`: `--hostname` (when `hostname -f` is not an FQDN), `--san DNS:x` / `--san IP:y`,
`--org`, `--no-resolve`, `--force` (new leaf key), `--regenerate-ca`, and `--ca-cert/--ca-key`. The last pair signs
with a shared CA, for example across a search head cluster.

Files are written to `$SPLUNK_HOME/etc/auth/kvstore/` (`--dir` to change):

| File | Mode | Contents |
| --- | --- | --- |
| `kvstore-ca.key` / `kvstore-ca.pem` | 0600 / 0644 | Local CA (10 years, `keyCertSign`, `cRLSign`) |
| `kvstore.key` / `kvstore.crt` | 0600 / 0644 | Leaf (10 years, `serverAuth` + `clientAuth`, SANs) |
| `kvstore-server.pem` | 0600 | Leaf cert, key, CA: the file `[kvstore] serverCert` points at |
| `ca-combined.pem` | 0644 | Trust file `[sslConfig] sslRootCAPath` points at |
| `manifest.json` | 0644 | Serials, fingerprints, expiry dates, trust source |

Exit codes: `0` success, `1` a check or step failed, `2` usage or environment error.

## Tests

```shell
python -m pytest
```

The tests run against a fake `$SPLUNK_HOME` whose `bin/splunk` stub answers `btool`, `cmd openssl` (using the system
`openssl`), and `show kvstore-status`.
