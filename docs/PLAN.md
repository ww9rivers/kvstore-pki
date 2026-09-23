# kvstore-pki Implementation Plan

## Goal

Automate the [split-certs runbook](../../../empf/ops/splunk/kvstore/failures.md#runbook-split-certs-incommon-on-the-ui-splunk-ca-on-the-kv-store):
issue a locally trusted, dual-EKU (`serverAuth` + `clientAuth`) certificate for
the loopback-only KV store (`mongod`, 8191), and wire it into `server.conf`
without touching the InCommon certificate served on 8000 (Splunk Web) and 8089
(splunkd management, monitored by Nagios XI).

Every manual step in the runbook that has failed at least once becomes a check
the tool runs itself: error 92 from a CA without `keyUsage`, a PEM with no key,
a key that does not match the cert, a stale `versionFile42`, and partial TLS
settings left in `[kvstore]`.

## Scope

In scope:

- A local CA with the extensions `openssl verify -x509_strict` requires.
- A KV store leaf certificate with both EKUs, and SANs for the FQDN, short
  hostname, host IP address(es), `localhost`, and `127.0.0.1`.
- The combined `kvstore-server.pem` and the `ca-combined.pem` trust file.
- Edits to `$SPLUNK_HOME/etc/system/local/server.conf` that keep comments and
  ordering intact.
- Checks before and after the change, including the version-marker check that
  can hide the fix.

Out of scope:

- Changing `web.conf` or the InCommon files under `/app/etc/ssl`.
- Restarting Splunk unless `--restart` is passed.
- `splunk clean kvstore --local`. It deletes data, so the tool only prints the
  command.
- Distributing a CA across a search head cluster. The tool supports signing
  with an existing CA (`--ca-cert/--ca-key`) so a shared CA can be used, but
  copying it between members stays manual.

## Generated artifacts

Default directory: `$SPLUNK_HOME/etc/auth/kvstore/`, mode `0700`, owned by
`splunk:splunk`.

| File | Contents | Mode |
| --- | --- | --- |
| `kvstore-ca.key` | CA private key, RSA 4096 | 0600 |
| `kvstore-ca.pem` | CA cert, 10 y. `basicConstraints=critical,CA:TRUE`; `keyUsage=critical,keyCertSign,cRLSign`; SKI | 0644 |
| `kvstore.key` | Leaf private key, RSA 2048, unencrypted (`0600` is sufficient) | 0600 |
| `kvstore.crt` | Leaf cert, 10 y. `CA:FALSE`; `keyUsage=critical,digitalSignature,keyEncipherment`; `EKU=serverAuth,clientAuth`; SAN; SKI and AKI | 0644 |
| `kvstore-server.pem` | `kvstore.crt` + `kvstore.key` + `kvstore-ca.pem`, in Splunk's documented order | 0600 |
| `ca-combined.pem` | Current `[sslConfig]/sslRootCAPath` contents (symlinks resolved) + `kvstore-ca.pem` | 0644 |
| `manifest.json` | Fingerprints, serials, expiry dates, the trust source path, and the tool version | 0644 |

The tool writes no `.csr`, `.srl`, or `-ext.cnf` files. Serials are random
(`x509.random_serial_number()`) and extensions are built in code.

## Package layout

```
kvstore_pki/
  __init__.py
  cli.py        # argparse entry point and subcommands
  pki.py        # CA and leaf generation, PEM assembly (cryptography)
  certcheck.py  # parse and validate existing PEMs: EKU, key match, chain, expiry
  splunk.py     # SPLUNK_HOME discovery, btool wrapper, `splunk cmd openssl`, status
  conf.py       # .conf editor that keeps comments and ordering
  hostinfo.py   # FQDN, short name, IP discovery
  fsutil.py     # atomic writes, chmod/chown, timestamped backups
tests/
  conftest.py (fake $SPLUNK_HOME)  test_pki.py  test_conf.py  test_cli.py
pyproject.toml   # modeled on ../certinext
```

- Runtime dependency: `cryptography>=38` only. The CLI uses `argparse` to keep
  installs on Splunk hosts small. Python `>=3.9` (RHEL 9 default).
- Dev dependency: `pytest`.
- Console script: `kvstore-pki = kvstore_pki.cli:main`.

## CLI

```
kvstore-pki [--splunk-home /app/splunk] [--dir DIR] [--dry-run] [-v] <command>

  check      Read-only diagnosis of the current host (safe to run any time)
  issue      Create or reuse the CA, issue the leaf, and build kvstore-server.pem
  trust      Rebuild ca-combined.pem from the current sslRootCAPath and the local CA
  configure  Back up and edit server.conf ([kvstore] and [sslConfig])
  verify     Checks after restart: mongod.log, port 8191, kvstore-status, 8089/8000 issuer
  setup      check → issue → trust → configure, then optionally --restart and verify
  expiry     Print expiry dates for the leaf and CA (for monitoring or cron)
```

Common options: `--hostname`, `--san DNS:x|IP:y` (repeatable, added to the
defaults), `--days`, `--ca-days`, `--key-size`, `--ca-cert/--ca-key` (use an
existing CA), `--force` (reissue the leaf with a new key even if it is
valid), `--regenerate-ca` (replace the local CA, which implies a new leaf),
`--no-resolve` (skip DNS lookup of host IPs), `--org`, `--owner splunk`.

### `check`

Runs the failures.md triage table and prints PASS/WARN/FAIL for each item with
a pointer to the matching section.

Checks 1 and 2 only report. The tool never renames the marker file or changes
`kvstoreUpgradeOnStartupEnabled`; it prints the fix from failures.md instead.

1. **Version marker**: warn if `var/run/splunk/kvstore_upgrade/versionFile42`
   exists or the `mongod-*` binary named in the latest `splunkd.log` start is
   missing. This causes the same 4 ms failure and would hide the fix.
2. **`kvstoreUpgradeOnStartupEnabled`** as btool resolves it.
3. **Resolved KV store cert**: the value of `[kvstore]/serverCert`, or
   `[sslConfig]/serverCert` if unset, from `btool server list --debug`. For
   that PEM, check that a private key is present, that the key matches the
   cert (compare public keys, not modulus), that the EKU has both purposes, and
   that nothing in it has expired.
4. **Partial TLS settings in `[kvstore]`**: flag `sslRootCAPath`, `caCertFile`,
   `caCertPath`, `sslVerifyServerName`, and `sslVerifyServerCert`.
5. **Chain**: run `splunk cmd openssl verify -x509_strict` against the
   resolved `sslRootCAPath`. Use Splunk's bundled OpenSSL, because that is the
   one splunkd uses.
6. **Liveness**: is 8191 listening, is `mongod` alive, does `mongod.log` have
   entries for this boot.

Exit code: 0 if everything passes, 1 if anything fails, 2 on a usage or
environment error.

### `issue`

- Reuse the CA if `kvstore-ca.pem` and `kvstore-ca.key` exist, match, are
  valid, and carry the required `keyUsage`. If an existing CA lacks
  `keyUsage` (error 92), stop with a clear message; `--regenerate-ca`
  replaces it. `--force` never touches a valid CA, so a routine leaf reissue
  cannot break the trust other hosts have in the CA.
- Reissue the leaf if it is missing, if it was not signed by the current CA,
  if the SAN set has changed, if it expires within 30 days, or if `--force` is
  passed. Otherwise do nothing.
- After every write, run all four runbook checks in-process and again with
  `splunk cmd openssl` (`-purpose`, key present, key match,
  `verify -x509_strict`). Fail loudly if the two results disagree.
- Write atomically (temp file, then `os.replace`) so a partial
  `kvstore-server.pem` is never left behind.

### `trust`

- Read `[sslConfig]/sslRootCAPath` as btool resolves it. If it already points
  at our `ca-combined.pem`, use the source recorded in `manifest.json`, so
  running `trust` again never includes our own output.
- Write the source CA bundle followed by `kvstore-ca.pem`, removing duplicate
  certs by fingerprint.
- Never modify the source (`incommon-ca.cer` / `cacert.pem`).
- Runs only when invoked (or as part of `setup`). It is not tied to any
  external CA's renewal cycle, and `check` does not track changes to the source.

### `configure`

- Back up to `server.conf.bak-YYYYmmdd-HHMMSS` before writing.
- `[kvstore]`: set `disabled = false` and
  `serverCert = <dir>/kvstore-server.pem`. Do not touch
  `kvstoreUpgradeOnStartupEnabled` or `sslPassword`; the leaf key is
  unencrypted. Comment out (do not delete) the deprecated keys listed in check 4,
  with a `# kvstore-pki: disabled` marker.
- `[sslConfig]`: set only `sslRootCAPath = <dir>/ca-combined.pem`. Leave
  `serverCert` alone, so 8089 keeps InCommon.
- After writing, run `btool server list kvstore --debug` and
  `btool server list sslConfig --debug`, and fail if a different app or file
  wins precedence for any key we set. btool reports the winning file.
- `--dry-run` prints a unified diff.

### `verify`

Implements runbook steps 6 and 7. Checks that `mongod.log` has lines newer than
the splunkd start time, that there is no `Failed to start mongod` in
`splunkd.log`, that 8191 is listening, and that `splunk show kvstore-status`
reports `ready`. It then runs `openssl s_client` equivalents
(`ssl.get_server_certificate`) against 8089 and 8000 and confirms the issuer is
still InCommon/Sectigo, not the local CA. `kvstore-status` needs credentials,
so it takes `--auth` or reads `SPLUNK_AUTH`. It never stores them.

## Implementation notes

- **conf.py** is a line-based editor, not `configparser`. `configparser` drops
  comments, rejects duplicate keys, and gets Splunk's `\` continuation lines
  wrong. It parses into a list of (stanza, line) records, edits in place,
  appends missing keys at the end of their stanza, and creates the stanza if it
  is missing. Tests use a round-trip fixture: parse and write with no edits
  must return the same bytes.
- **Host discovery**: use `socket.getfqdn()`, and fail if the result has no
  dot, unless `--hostname` is given. Collect non-loopback IPv4 addresses from
  `socket.getaddrinfo(fqdn)`. The README requires the host IP, which the
  runbook omitted.
- **Privileges**: `issue` and `configure` must run as root (then chown to
  `--owner`) or as the owner user. Refuse to run as another user, so the files
  never end up unreadable by splunkd.
- **Time skew** (error 9): backdate `not_valid_before` by 5 minutes.
- **Key match**: compare `public_key().public_numbers()`, or DER of the
  SubjectPublicKeyInfo. This works for EC keys too, where the runbook's
  modulus check does not.

## Testing

- Unit tests: generate into `tmp_path`, then check extensions with
  `cryptography` and, where `openssl` is on PATH, with
  `openssl verify -x509_strict` and `openssl x509 -purpose`. That OpenSSL is
  3.0.13 locally, the same version the error-92 reproduction used.
- Regression test: a CA built without `keyUsage` must be rejected by `issue`,
  and must fail `verify -x509_strict`. This locks in error 92.
- Conf tests: the round trip, deprecated keys commented out, a missing stanza
  created, and continuation lines preserved.
- CLI tests: a fake `$SPLUNK_HOME` tree, with a stub `bin/splunk` script that
  returns canned btool output.
- Manual acceptance on a test host: `check`, then `setup --restart`, then
  `verify`, then the runbook step 7 comparison.

## Milestones

1. Scaffold `pyproject.toml`, the package, and the test harness.
2. `pki.py` and `certcheck.py` with unit tests. This is the core and can be used
   on its own.
3. `issue` and `trust` subcommands, plus the manifest.
4. `conf.py` and `configure`, with the round-trip tests.
5. `splunk.py`: btool, `splunk cmd openssl`, and the `check` and `verify`
   commands.
6. `setup` orchestration, `expiry`, and README usage docs.

## Decisions

- `kvstoreUpgradeOnStartupEnabled` and `versionFile42` are reported by `check`,
  never fixed by the tool.
- Rebuilding `ca-combined.pem` is not tied to the InCommon renewal. It runs
  only when `trust` or `setup` is invoked.
- The leaf key stays unencrypted with mode `0600`. There is no
  `--encrypt-key` option and no `sslPassword` handling.
