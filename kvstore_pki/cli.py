"""
kvstore-pki command line.

Implements the split-certs runbook: a local CA and a dual-EKU certificate for
the loopback-only KV store, with the InCommon certificate left on 8000/8089.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import ssl
import subprocess
import sys
import time
from typing import List, Optional, Sequence

from cryptography import x509

from kvstore_pki import __version__, certcheck, conf, fsutil, hostinfo, pki
from kvstore_pki.certcheck import FAIL, PASS, WARN, Result
from kvstore_pki.splunk import (
    KVSTORE_PORT,
    Splunk,
    SplunkError,
    find_home,
    mongod_running,
    port_open,
)

# Settings in [kvstore] that break 10.x inheritance from [sslConfig], or are
# deprecated there (failures.md §1 and "Corrections to the config block").
DEPRECATED_KVSTORE_KEYS = (
    "sslRootCAPath",
    "caCertFile",
    "caCertPath",
    "sslVerifyServerName",
    "sslVerifyServerCert",
)
RENEW_WITHIN_DAYS = 30


class UsageError(Exception):
    """Bad arguments or environment: exit code 2."""


class CommandFailed(Exception):
    """A check or step failed: exit code 1."""


class Layout:
    """Paths of the files kept in the output directory."""

    def __init__(self, directory: str):
        self.directory = directory
        self.ca_key = os.path.join(directory, "kvstore-ca.key")
        self.ca_pem = os.path.join(directory, "kvstore-ca.pem")
        self.key = os.path.join(directory, "kvstore.key")
        self.crt = os.path.join(directory, "kvstore.crt")
        self.bundle = os.path.join(directory, "kvstore-server.pem")
        self.combined = os.path.join(directory, "ca-combined.pem")
        self.manifest = os.path.join(directory, "manifest.json")


class Context:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.splunk = Splunk(find_home(args.splunk_home))
        self.layout = Layout(os.path.abspath(args.dir or self.splunk.default_dir))
        self.dry_run = args.dry_run
        self.verbose = args.verbose
        self.now = pki.utcnow()
        self._ids = None
        self._ids_resolved = False

    @property
    def ids(self):
        """(uid, gid) to chown written files to, or None; raises if not allowed."""
        if not self._ids_resolved:
            try:
                self._ids = fsutil.resolve_owner(self.args.owner)
            except fsutil.OwnerError as exc:
                raise UsageError(str(exc)) from None
            self._ids_resolved = True
        return self._ids

    def say(self, message: str) -> None:
        print(message)

    def write(self, path: str, data: bytes, mode: int) -> None:
        if self.dry_run:
            self.say(f"would write {path} (mode {mode:04o})")
            return
        fsutil.write_file(path, data, mode, self.ids)
        if self.verbose:
            self.say(f"wrote {path}")

    def load_manifest(self) -> dict:
        data = fsutil.read_optional(self.layout.manifest)
        return json.loads(data) if data else {}

    def save_manifest(self, updates: dict) -> None:
        manifest = self.load_manifest()
        manifest.update(updates)
        manifest["tool_version"] = __version__
        manifest["updated"] = self.now.isoformat(timespec="seconds")
        body = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
        self.write(self.layout.manifest, body, 0o644)


def report(results: Sequence[Result]) -> None:
    for r in results:
        print(f"  {r}")


def cert_record(cert: x509.Certificate) -> dict:
    return {
        "subject": cert.subject.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "sha256": certcheck.fingerprint(cert),
        "not_after": certcheck.not_after(cert).isoformat(timespec="seconds"),
    }


# -- check ---------------------------------------------------------------------


def check_version_marker(ctx: Context) -> List[Result]:
    results = []
    markers = ctx.splunk.version_markers()
    if "versionFile42" in markers:
        results.append(
            Result(
                WARN,
                "version marker",
                "versionFile42 present; 10.x has no mongod-4.2. Fix: "
                "mv versionFile42 versionFile80 in var/run/splunk/kvstore_upgrade "
                "(failures.md, Version Mismatch)",
            )
        )
    else:
        results.append(Result(PASS, "version marker", ", ".join(markers) or "none"))
    exe = ctx.splunk.mongod_executable()
    if exe:
        if os.path.exists(ctx.splunk.path("bin", exe)):
            results.append(Result(PASS, "mongod binary", f"bin/{exe} exists"))
        else:
            results.append(
                Result(FAIL, "mongod binary", f"splunkd.log starts {exe}, but bin/{exe} is missing")
            )
    return results


def check_upgrade_flag(ctx: Context) -> Result:
    value = ctx.splunk.setting("kvstore", "kvstoreUpgradeOnStartupEnabled")
    if value is not None and value.lower() in ("true", "1"):
        return Result(PASS, "kvstoreUpgradeOnStartupEnabled", value)
    return Result(
        WARN,
        "kvstoreUpgradeOnStartupEnabled",
        f"{value or 'unset'}; set it to true in [kvstore] (failures.md, Version Mismatch)",
    )


def resolved_server_cert(ctx: Context) -> str:
    value = ctx.splunk.setting("kvstore", "serverCert") or ctx.splunk.setting(
        "sslConfig", "serverCert", "$SPLUNK_HOME/etc/auth/server.pem"
    )
    return ctx.splunk.expand(value)


def resolved_root_ca(ctx: Context) -> str:
    return ctx.splunk.expand(
        ctx.splunk.setting("sslConfig", "sslRootCAPath", "$SPLUNK_HOME/etc/auth/cacert.pem")
    )


def check_server_cert(ctx: Context, path: str) -> List[Result]:
    data = fsutil.read_optional(path)
    if data is None:
        return [Result(FAIL, "KV store cert", f"{path} does not exist")]
    results = [Result(PASS, "KV store cert", path)]
    results += [
        Result(r.status, f"KV store cert {r.name}", r.detail)
        for r in certcheck.inspect_server_pem(data, ctx.now)
    ]
    return results


def check_deprecated(ctx: Context) -> List[Result]:
    settings = ctx.splunk.btool("server", "kvstore")
    found = [
        f"{k} (in {settings[k].file})" for k in DEPRECATED_KVSTORE_KEYS if k in settings
    ]
    if found:
        return [
            Result(
                WARN,
                "[kvstore] partial TLS settings",
                ", ".join(found) + " (failures.md §1)",
            )
        ]
    return [Result(PASS, "[kvstore] partial TLS settings", "none")]


def check_chain(ctx: Context, cert_path: str, root: str) -> Result:
    if not os.path.exists(root):
        return Result(FAIL, "chain", f"sslRootCAPath {root} does not exist")
    if not os.path.exists(cert_path):
        return Result(FAIL, "chain", f"{cert_path} does not exist")
    res = ctx.splunk.openssl(
        ["verify", "-verbose", "-x509_strict", "-CAfile", root, "-untrusted", cert_path, cert_path]
    )
    lines = [l for l in res.output.strip().splitlines() if l.strip()]
    detail = f"{res.label} verify -x509_strict against {root}: "
    if res.ok:
        return Result(PASS, "chain", detail + "OK")
    return Result(FAIL, "chain", detail + " | ".join(lines[-3:]))


def check_liveness(ctx: Context) -> List[Result]:
    port = int(ctx.splunk.setting("kvstore", "port", str(KVSTORE_PORT)))
    results = []
    if port_open("127.0.0.1", port):
        results.append(Result(PASS, "port", f"something is listening on {port}"))
    else:
        results.append(Result(FAIL, "port", f"nothing listening on 127.0.0.1:{port}"))
    results.append(
        Result(PASS, "mongod process", "running")
        if mongod_running()
        else Result(FAIL, "mongod process", "not running")
    )
    results.append(check_mongod_log(ctx))
    return results


def check_mongod_log(ctx: Context) -> Result:
    path = ctx.splunk.log("mongod.log")
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return Result(FAIL, "mongod.log", "absent: mongod never started (failures.md, triage A)")
    boot = ctx.splunk.boot_time()
    if st.st_size == 0:
        return Result(FAIL, "mongod.log", "empty: mongod never started (failures.md, triage A)")
    if boot is not None and st.st_mtime < boot:
        return Result(
            FAIL, "mongod.log", "no entries since splunkd started: mongod never started this boot"
        )
    return Result(PASS, "mongod.log", "has entries for this boot")


def cmd_check(ctx: Context) -> int:
    results: List[Result] = []
    sections = [
        ("Version marker", lambda: check_version_marker(ctx)),
        ("Upgrade on startup", lambda: [check_upgrade_flag(ctx)]),
        ("KV store certificate", lambda: check_server_cert(ctx, resolved_server_cert(ctx))),
        ("[kvstore] stanza", lambda: check_deprecated(ctx)),
        ("Trust chain", lambda: [check_chain(ctx, resolved_server_cert(ctx), resolved_root_ca(ctx))]),
        ("Liveness", lambda: check_liveness(ctx)),
    ]
    for title, fn in sections:
        print(title)
        try:
            section = fn()
        except SplunkError as exc:
            section = [Result(FAIL, title, str(exc))]
        report(section)
        results += section
    return 1 if certcheck.any_failed(results) else 0


# -- issue ---------------------------------------------------------------------


def load_ca(ctx: Context):
    """Return (ca_cert, ca_key, ca_key_path, created)."""
    args, lay = ctx.args, ctx.layout
    if args.ca_cert or args.ca_key:
        if not (args.ca_cert and args.ca_key):
            raise UsageError("--ca-cert and --ca-key must be given together")
        cert_data = fsutil.read_file(args.ca_cert)
        certs = certcheck.load_certs(cert_data)
        key = certcheck.load_private_key(fsutil.read_file(args.ca_key))
        if not certs or key is None:
            raise UsageError("--ca-cert must hold a certificate and --ca-key a private key")
        validate_ca(ctx, certs[0], key, "--ca-cert")
        return certs[0], key, os.path.abspath(args.ca_key), False

    have_pem = os.path.exists(lay.ca_pem)
    have_key = os.path.exists(lay.ca_key)
    if args.regenerate_ca or not (have_pem or have_key):
        key = pki.new_key(args.ca_key_size)
        cert = pki.make_ca(key, org=args.org, days=args.ca_days, now=ctx.now)
        ctx.say(("regenerating" if have_pem else "creating") + f" CA {cert.subject.rfc4514_string()}")
        return cert, key, lay.ca_key, True
    if have_pem != have_key:
        raise CommandFailed(
            f"only one of {lay.ca_pem} and {lay.ca_key} exists; pass --regenerate-ca"
        )
    certs = certcheck.load_certs(fsutil.read_file(lay.ca_pem))
    key = certcheck.load_private_key(fsutil.read_file(lay.ca_key))
    if not certs or key is None:
        raise CommandFailed(f"cannot load the CA from {lay.directory}; pass --regenerate-ca")
    validate_ca(ctx, certs[0], key, lay.ca_pem)
    ctx.say(f"reusing CA {certcheck.describe(certs[0])}")
    return certs[0], key, lay.ca_key, False


def validate_ca(ctx: Context, cert, key, where: str) -> None:
    problems = certcheck.ca_problems(cert) + certcheck.validity_problems(cert, ctx.now, "CA")
    if not certcheck.key_matches(cert, key):
        problems.append("CA key does not match CA certificate")
    if certcheck.days_left(cert, ctx.now) < RENEW_WITHIN_DAYS:
        problems.append(f"CA expires within {RENEW_WITHIN_DAYS} days")
    if problems:
        hint = "" if ctx.args.ca_cert else "; pass --regenerate-ca to replace it"
        raise CommandFailed(f"{where}: " + "; ".join(problems) + hint)


def leaf_reasons(ctx: Context, ca_cert, ca_created: bool, sans: List[str]):
    """Return (reasons to reissue, existing key to reuse or None)."""
    lay, args = ctx.layout, ctx.args
    reasons = []
    key = None
    key_data = fsutil.read_optional(lay.key)
    if key_data is not None and not args.force:
        try:
            key = certcheck.load_private_key(key_data)
        except ValueError:
            key = None
        if key is not None and key.key_size != args.key_size:
            key = None
    crt_data = fsutil.read_optional(lay.crt)
    certs = certcheck.load_certs(crt_data) if crt_data else []
    if args.force:
        reasons.append("--force")
    if ca_created:
        reasons.append("new CA")
    if not certs:
        reasons.append("no leaf certificate")
        return reasons, key
    leaf = certs[0]
    if not certcheck.issued_by(leaf, ca_cert):
        reasons.append("leaf was not signed by the current CA")
    if certcheck.san_strings(leaf) != set(sans):
        reasons.append("SAN list changed")
    if certcheck.days_left(leaf, ctx.now) < RENEW_WITHIN_DAYS:
        reasons.append(f"leaf expires within {RENEW_WITHIN_DAYS} days")
    if certcheck.purposes(leaf) != (True, True):
        reasons.append("leaf lacks serverAuth + clientAuth")
    if key is None:
        reasons.append("leaf key missing or replaced")
    elif not certcheck.key_matches(leaf, key):
        reasons.append("leaf key does not match leaf certificate")
        key = None
    return reasons, key


def verify_material(ctx: Context) -> List[Result]:
    """The four runbook step 3 checks, in-process and with OpenSSL; they must agree."""
    lay = ctx.layout
    bundle = fsutil.read_file(lay.bundle)
    leaf = certcheck.load_certs(fsutil.read_file(lay.crt))[0]
    ca = certcheck.load_certs(fsutil.read_file(lay.ca_pem))[0]
    key = certcheck.load_private_key(fsutil.read_file(lay.key))

    local = {
        "purpose": certcheck.purposes(certcheck.load_certs(bundle)[0]) == (True, True),
        "key present": bool(certcheck.private_key_blocks(bundle)),
        "key match": certcheck.key_matches(leaf, key),
        "chain": not certcheck.chain_problems(leaf, [ca], ctx.now),
    }

    res = ctx.splunk.openssl(["x509", "-noout", "-purpose", "-in", lay.bundle])
    purpose_out = res.proc.stdout
    server = re.search(r"^SSL server\s*:\s*Yes", purpose_out, re.M) is not None
    client = re.search(r"^SSL client\s*:\s*Yes", purpose_out, re.M) is not None
    pub_crt = ctx.splunk.openssl(["x509", "-noout", "-pubkey", "-in", lay.crt]).proc.stdout
    pub_key = ctx.splunk.openssl(["pkey", "-pubout", "-in", lay.key]).proc.stdout
    chain = ctx.splunk.openssl(
        ["verify", "-verbose", "-x509_strict", "-CAfile", lay.ca_pem, lay.crt]
    )
    remote = {
        "purpose": res.ok and server and client,
        "key present": local["key present"],  # the runbook's grep; nothing to compare
        "key match": bool(pub_crt.strip()) and pub_crt == pub_key,
        "chain": chain.ok and f"{lay.crt}: OK" in chain.proc.stdout,
    }

    results = []
    for name in local:
        if local[name] and remote[name]:
            results.append(Result(PASS, name, f"in-process and {res.label} agree"))
        elif local[name] != remote[name]:
            results.append(
                Result(
                    FAIL,
                    name,
                    f"in-process says {'OK' if local[name] else 'FAIL'}, "
                    f"{res.label} says {'OK' if remote[name] else 'FAIL'}",
                )
            )
        else:
            detail = chain.output.strip() if name == "chain" else "failed both checks"
            results.append(Result(FAIL, name, detail))
    if not res.bundled:
        results.append(
            Result(WARN, "openssl", "bin/splunk not found; used the system openssl, not Splunk's")
        )
    return results


def cmd_issue(ctx: Context) -> int:
    args, lay = ctx.args, ctx.layout
    try:
        sans = hostinfo.host_sans(args.hostname, args.san, resolve=not args.no_resolve)
    except (hostinfo.HostError, ValueError) as exc:
        raise UsageError(str(exc)) from None
    common_name = sans[0].partition(":")[2]

    ca_cert, ca_key, ca_key_path, ca_created = load_ca(ctx)
    reasons, key = leaf_reasons(ctx, ca_cert, ca_created, sans)

    if not ctx.dry_run:
        fsutil.ensure_dir(lay.directory, 0o700, ctx.ids)
    else:
        ctx.ids  # still refuse to plan as the wrong user

    ca_pem = pki.cert_pem(ca_cert)
    if ca_created:
        ctx.write(lay.ca_key, pki.key_pem(ca_key), 0o600)
    if fsutil.read_optional(lay.ca_pem) != ca_pem:
        ctx.write(lay.ca_pem, ca_pem, 0o644)

    if reasons:
        ctx.say("issuing leaf: " + "; ".join(reasons))
        if key is None:
            key = pki.new_key(args.key_size)
            ctx.write(lay.key, pki.key_pem(key), 0o600)
        leaf = pki.make_leaf(
            ca_cert, ca_key, key, common_name, sans, org=args.org, days=args.days, now=ctx.now
        )
        leaf_pem = pki.cert_pem(leaf)
        ctx.write(lay.crt, leaf_pem, 0o644)
    else:
        leaf_pem = fsutil.read_file(lay.crt)
        leaf = certcheck.load_certs(leaf_pem)[0]
        ctx.say(f"leaf is current: {certcheck.describe(leaf)}")

    key_bytes = pki.key_pem(key)
    bundle = pki.server_bundle(leaf_pem, key_bytes, ca_pem)
    if fsutil.read_optional(lay.bundle) != bundle:
        ctx.write(lay.bundle, bundle, 0o600)

    ctx.say(f"SAN: {', '.join(sans)}")
    if ctx.dry_run:
        return 0

    ctx.save_manifest(
        {
            "directory": lay.directory,
            "ca": dict(cert_record(ca_cert), key_path=ca_key_path),
            "leaf": dict(cert_record(leaf), sans=sans),
        }
    )
    print("Verification")
    results = verify_material(ctx)
    report(results)
    return 1 if certcheck.any_failed(results) else 0


# -- trust ---------------------------------------------------------------------


def cmd_trust(ctx: Context) -> int:
    lay = ctx.layout
    ca_data = fsutil.read_optional(lay.ca_pem)
    if ca_data is None and ctx.dry_run:
        ctx.say(f"would build {lay.combined} once {lay.ca_pem} exists")
        return 0
    if ca_data is None:
        raise CommandFailed(f"{lay.ca_pem} does not exist; run 'issue' first")
    root = resolved_root_ca(ctx)
    manifest = ctx.load_manifest()
    if os.path.exists(root) and os.path.exists(lay.combined) and os.path.samefile(root, lay.combined):
        source = manifest.get("trust_source")
        if not source:
            raise CommandFailed(
                f"sslRootCAPath already points at {lay.combined} and manifest.json "
                "does not record the original trust source"
            )
    else:
        source = root
    source_data = fsutil.read_optional(source)
    if source_data is None:
        raise CommandFailed(f"trust source {source} does not exist")

    seen = set()
    blocks = []
    for cert in certcheck.load_certs(source_data) + certcheck.load_certs(ca_data):
        fp = certcheck.fingerprint(cert)
        if fp not in seen:
            seen.add(fp)
            blocks.append(pki.cert_pem(cert))
    if len(blocks) == len(certcheck.load_certs(ca_data)):
        raise CommandFailed(f"trust source {source} contains no certificates")

    combined = b"".join(blocks)
    ctx.say(f"trust source: {source} ({len(blocks) - 1} cert(s)) + {lay.ca_pem}")
    if fsutil.read_optional(lay.combined) == combined:
        ctx.say(f"{lay.combined} is current")
    else:
        ctx.write(lay.combined, combined, 0o644)
    if manifest.get("trust_source") != source and not ctx.dry_run:
        ctx.save_manifest({"trust_source": source})
    return 0


# -- configure -----------------------------------------------------------------


def desired_settings(ctx: Context):
    lay = ctx.layout
    return [
        ("kvstore", "disabled", "false"),
        ("kvstore", "serverCert", lay.bundle),
        ("sslConfig", "sslRootCAPath", lay.combined),
    ]


def cmd_configure(ctx: Context) -> int:
    lay, path = ctx.layout, ctx.splunk.local_server_conf
    for needed in (lay.bundle, lay.combined):
        if not os.path.exists(needed):
            if ctx.dry_run:
                ctx.say(f"note: {needed} does not exist yet")
            else:
                raise CommandFailed(f"{needed} does not exist; run 'issue' and 'trust' first")

    original = fsutil.read_optional(path)
    text = original.decode() if original is not None else ""
    cf = conf.ConfFile.parse(text)
    for stanza, key, value in desired_settings(ctx):
        cf.set(stanza, key, value)
    for key in DEPRECATED_KVSTORE_KEYS:
        if cf.comment_out("kvstore", key):
            ctx.say(f"commenting out [kvstore] {key}")
    new = cf.render()

    if new == text:
        ctx.say(f"{path} already configured")
    else:
        diff = difflib.unified_diff(
            text.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=path,
            tofile=path + " (new)",
        )
        sys.stdout.writelines(diff)
        if ctx.dry_run:
            return 0
        ctx.ids  # enforce the owner rule before touching server.conf
        if original is None:
            fsutil.ensure_dir(os.path.dirname(path), 0o755)
            fsutil.write_file(path, new.encode(), 0o600, ctx.ids)
        else:
            ctx.say(f"backup: {fsutil.backup(path)}")
            fsutil.replace_preserving(path, new.encode())
        ctx.say(f"updated {path}")
    if ctx.dry_run:
        return 0

    print("Resolved configuration (btool)")
    results = check_precedence(ctx)
    report(results)
    return 1 if certcheck.any_failed(results) else 0


def check_precedence(ctx: Context) -> List[Result]:
    local = os.path.realpath(ctx.splunk.local_server_conf)
    results = []
    by_stanza = {}
    for stanza, key, value in desired_settings(ctx):
        settings = by_stanza.setdefault(stanza, ctx.splunk.btool("server", stanza))
        found = settings.get(key)
        name = f"[{stanza}] {key}"
        if found is None:
            results.append(Result(FAIL, name, "not visible to btool"))
        elif ctx.splunk.expand(found.value) != value:
            results.append(Result(FAIL, name, f"{found.value} from {found.file} overrides ours"))
        elif os.path.realpath(found.file) != local:
            results.append(Result(WARN, name, f"resolved from {found.file}"))
        else:
            results.append(Result(PASS, name, found.value))
    leftovers = [k for k in DEPRECATED_KVSTORE_KEYS if k in by_stanza["kvstore"]]
    for key in leftovers:
        results.append(
            Result(WARN, f"[kvstore] {key}", f"still set in {by_stanza['kvstore'][key].file}")
        )
    return results


# -- verify --------------------------------------------------------------------


def served_cert(host: str, port: int) -> x509.Certificate:
    pem = ssl.get_server_certificate((host, port), timeout=5)
    return x509.load_pem_x509_certificate(pem.encode())


def cmd_verify(ctx: Context) -> int:
    args, lay = ctx.args, ctx.layout
    results: List[Result] = []
    log = ctx.splunk.read_log("splunkd.log")
    if log is None:
        results.append(Result(WARN, "splunkd.log", "not found"))
    elif "Failed to start mongod" in ctx.splunk.since_last_start(log):
        results.append(Result(FAIL, "splunkd.log", "'Failed to start mongod' since the last start"))
    else:
        results.append(Result(PASS, "splunkd.log", "no 'Failed to start mongod' since the last start"))
    results.append(check_mongod_log(ctx))

    port = int(ctx.splunk.setting("kvstore", "port", str(KVSTORE_PORT)))
    if port_open("127.0.0.1", port):
        results.append(Result(PASS, "port", f"listening on {port}"))
        results.append(check_served_kvstore(ctx, port))
    else:
        results.append(Result(FAIL, "port", f"nothing listening on 127.0.0.1:{port}"))

    auth = args.auth or os.environ.get("SPLUNK_AUTH")
    if auth:
        proc = ctx.splunk.kvstore_status(auth)
        if proc.returncode == 0 and re.search(r"status\s*:\s*ready", proc.stdout):
            results.append(Result(PASS, "kvstore-status", "ready"))
        else:
            tail = (proc.stdout + proc.stderr).strip().splitlines()[-3:]
            results.append(Result(FAIL, "kvstore-status", " | ".join(tail) or "not ready"))
    else:
        results.append(Result(WARN, "kvstore-status", "skipped; pass --auth or set SPLUNK_AUTH"))

    ca = certcheck.load_certs(fsutil.read_optional(lay.ca_pem) or b"")
    host = args.hostname or hostinfo.discover_fqdn()
    for label, p in (("management", args.mgmt_port), ("web", args.web_port)):
        name = f"{label} port {p} issuer"
        try:
            cert = served_cert(host, p)
        except (OSError, ssl.SSLError, ValueError) as exc:
            results.append(Result(WARN, name, f"cannot fetch certificate from {host}:{p}: {exc}"))
            continue
        issuer = cert.issuer.rfc4514_string()
        if ca and cert.issuer == ca[0].subject:
            results.append(Result(FAIL, name, f"serves the local KV store CA ({issuer})"))
        else:
            results.append(Result(PASS, name, issuer))

    report(results)
    return 1 if certcheck.any_failed(results) else 0


def check_served_kvstore(ctx: Context, port: int) -> Result:
    leaf = certcheck.load_certs(fsutil.read_optional(ctx.layout.crt) or b"")
    try:
        served = served_cert("127.0.0.1", port)
    except (OSError, ssl.SSLError, ValueError) as exc:
        return Result(WARN, "KV store cert served", f"cannot fetch: {exc}")
    if leaf and certcheck.fingerprint(served) == certcheck.fingerprint(leaf[0]):
        return Result(PASS, "KV store cert served", "matches kvstore.crt")
    return Result(FAIL, "KV store cert served", f"{served.subject.rfc4514_string()}, not kvstore.crt")


# -- setup ---------------------------------------------------------------------


def wait_for_port(port: int, timeout: int) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open("127.0.0.1", port):
            return True
        time.sleep(5)
    return False


def cmd_setup(ctx: Context) -> int:
    print("== check (before) ==")
    cmd_check(ctx)  # informational: the current cert is expected to fail
    for title, fn in (("issue", cmd_issue), ("trust", cmd_trust), ("configure", cmd_configure)):
        print(f"== {title} ==")
        if fn(ctx) != 0:
            raise CommandFailed(f"{title} failed; stopping before any restart")
    if ctx.dry_run:
        return 0
    if not ctx.args.restart:
        print("== next steps ==")
        print(f"  sudo systemctl restart {ctx.args.service}")
        print("  kvstore-pki verify --auth admin:<password>")
        return 0
    print(f"== restart {ctx.args.service} ==")
    proc = subprocess.run(["systemctl", "restart", ctx.args.service], capture_output=True, text=True)
    if proc.returncode != 0:
        raise CommandFailed(f"systemctl restart failed: {proc.stderr.strip()}")
    port = int(ctx.splunk.setting("kvstore", "port", str(KVSTORE_PORT)))
    if not wait_for_port(port, ctx.args.wait):
        print(f"  KV store port {port} did not open within {ctx.args.wait}s")
    print("== verify ==")
    return cmd_verify(ctx)


# -- expiry --------------------------------------------------------------------


def cmd_expiry(ctx: Context) -> int:
    lay = ctx.layout
    status = 0
    for label, path in (("CA", lay.ca_pem), ("leaf", lay.crt)):
        certs = certcheck.load_certs(fsutil.read_optional(path) or b"")
        if not certs:
            print(f"[FAIL] {label}: {path} missing")
            status = 1
            continue
        left = certcheck.days_left(certs[0], ctx.now)
        flag = FAIL if left < ctx.args.warn_days else PASS
        if flag == FAIL:
            status = 1
        print(f"[{flag}] {label}: {certcheck.not_after(certs[0]):%Y-%m-%d} ({left} days) {path}")
    return status


# -- argument parsing ----------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kvstore-pki",
        description="Issue and configure a dual-EKU certificate for the Splunk KV store.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--splunk-home", help="default: $SPLUNK_HOME, /app/splunk, /opt/splunk")
    parser.add_argument("--dir", help="output directory (default: $SPLUNK_HOME/etc/auth/kvstore)")
    parser.add_argument("--owner", default="splunk", help="owner of written files (default: splunk)")
    parser.add_argument("--dry-run", action="store_true", help="show what would change")
    parser.add_argument("-v", "--verbose", action="store_true")

    host = argparse.ArgumentParser(add_help=False)
    host.add_argument("--hostname", help="host FQDN (default: socket.getfqdn())")

    certopts = argparse.ArgumentParser(add_help=False, parents=[host])
    certopts.add_argument("--san", action="append", default=[], metavar="DNS:x|IP:y",
                          help="extra SAN entry (repeatable)")
    certopts.add_argument("--no-resolve", action="store_true",
                          help="do not add the host's IPv4 addresses from DNS")
    certopts.add_argument("--org", help="O= attribute for CA and leaf subjects")
    certopts.add_argument("--days", type=int, default=pki.DEFAULT_DAYS, help="leaf lifetime")
    certopts.add_argument("--ca-days", type=int, default=pki.DEFAULT_DAYS, help="CA lifetime")
    certopts.add_argument("--key-size", type=int, default=2048, help="leaf RSA key size")
    certopts.add_argument("--ca-key-size", type=int, default=4096, help="CA RSA key size")
    certopts.add_argument("--ca-cert", help="sign with this existing CA certificate")
    certopts.add_argument("--ca-key", help="private key for --ca-cert")
    certopts.add_argument("--force", action="store_true", help="reissue the leaf with a new key")
    certopts.add_argument("--regenerate-ca", action="store_true",
                          help="replace the local CA (implies a new leaf)")

    verifyopts = argparse.ArgumentParser(add_help=False)
    verifyopts.add_argument("--auth", help="user:password for kvstore-status (or SPLUNK_AUTH)")
    verifyopts.add_argument("--mgmt-port", type=int, default=8089)
    verifyopts.add_argument("--web-port", type=int, default=8000)

    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")
    sub.add_parser("check", help="read-only diagnosis of this host")
    sub.add_parser("issue", parents=[certopts], help="create or reuse the CA and issue the leaf")
    sub.add_parser("trust", help="rebuild ca-combined.pem")
    sub.add_parser("configure", help="back up and edit server.conf")
    sub.add_parser("verify", parents=[host, verifyopts], help="checks after restart")
    setup = sub.add_parser("setup", parents=[certopts, verifyopts],
                           help="check, issue, trust, configure (then optionally restart)")
    setup.add_argument("--restart", action="store_true", help="restart Splunk and run verify")
    setup.add_argument("--service", default="Splunkd", help="systemd unit (default: Splunkd)")
    setup.add_argument("--wait", type=int, default=300, help="seconds to wait for the KV store port")
    expiry = sub.add_parser("expiry", help="print CA and leaf expiry dates")
    expiry.add_argument("--warn-days", type=int, default=RENEW_WITHIN_DAYS)
    return parser


COMMANDS = {
    "check": cmd_check,
    "issue": cmd_issue,
    "trust": cmd_trust,
    "configure": cmd_configure,
    "verify": cmd_verify,
    "setup": cmd_setup,
    "expiry": cmd_expiry,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = Context(args)
        return COMMANDS[args.command](ctx)
    except (UsageError, SplunkError, hostinfo.HostError) as exc:
        print(f"kvstore-pki: error: {exc}", file=sys.stderr)
        return 2
    except CommandFailed as exc:
        print(f"kvstore-pki: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
