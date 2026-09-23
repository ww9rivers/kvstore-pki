import json
import os
import stat

import pytest

from kvstore_pki import certcheck, cli, pki
from kvstore_pki.conf import DISABLED_MARKER, ConfFile

HOST = ["--hostname", "kv1.example.edu", "--no-resolve", "--ca-key-size", "2048"]


@pytest.fixture
def run(splunk_home, owner, capsys):
    def _run(*argv):
        code = cli.main(["--splunk-home", str(splunk_home), "--owner", owner, *argv])
        out = capsys.readouterr()
        return code, out.out + out.err

    return _run


def kvdir(home):
    return home / "etc" / "auth" / "kvstore"


def mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_issue_creates_material_with_modes(run, splunk_home):
    code, out = run("issue", *HOST)
    assert code == 0, out
    d = kvdir(splunk_home)
    assert mode(d) == 0o700
    assert mode(d / "kvstore-ca.key") == 0o600
    assert mode(d / "kvstore.key") == 0o600
    assert mode(d / "kvstore-server.pem") == 0o600
    assert mode(d / "kvstore-ca.pem") == 0o644
    assert mode(d / "kvstore.crt") == 0o644
    for name in ("purpose", "key present", "key match", "chain"):
        assert f"[PASS] {name}" in out
    manifest = json.loads((d / "manifest.json").read_text())
    assert "DNS:localhost" in manifest["leaf"]["sans"]
    assert "IP:127.0.0.1" in manifest["leaf"]["sans"]
    assert not list(d.glob(".kvstore-pki-*"))


def test_issue_is_idempotent_and_reuses_key_on_san_change(run, splunk_home):
    run("issue", *HOST)
    d = kvdir(splunk_home)
    before = {p.name: p.read_bytes() for p in d.iterdir()}
    code, out = run("issue", *HOST)
    assert code == 0 and "reusing CA" in out and "leaf is current" in out
    for name in ("kvstore-ca.pem", "kvstore-ca.key", "kvstore.key", "kvstore.crt", "kvstore-server.pem"):
        assert (d / name).read_bytes() == before[name]

    code, out = run("issue", *HOST, "--san", "IP:10.1.2.3")
    assert code == 0 and "SAN list changed" in out
    assert (d / "kvstore.key").read_bytes() == before["kvstore.key"]
    leaf = certcheck.load_certs((d / "kvstore.crt").read_bytes())[0]
    assert "IP:10.1.2.3" in certcheck.san_strings(leaf)


def test_issue_force_rotates_key(run, splunk_home):
    run("issue", *HOST)
    key = (kvdir(splunk_home) / "kvstore.key").read_bytes()
    code, _ = run("issue", *HOST, "--force")
    assert code == 0
    assert (kvdir(splunk_home) / "kvstore.key").read_bytes() != key


def test_issue_refuses_ca_without_key_usage(run, splunk_home):
    from tests.test_pki import ca_without_key_usage

    d = kvdir(splunk_home)
    d.mkdir(mode=0o700)
    ca, key = ca_without_key_usage()
    (d / "kvstore-ca.pem").write_bytes(pki.cert_pem(ca))
    (d / "kvstore-ca.key").write_bytes(pki.key_pem(key))
    code, out = run("issue", *HOST)
    assert code == 1
    assert "error 92" in out and "--regenerate-ca" in out

    code, out = run("issue", *HOST, "--regenerate-ca")
    assert code == 0, out
    new_ca = certcheck.load_certs((d / "kvstore-ca.pem").read_bytes())[0]
    assert certcheck.ca_problems(new_ca) == []


def test_issue_with_external_ca(run, splunk_home, tmp_path):
    ca_key = pki.new_key(2048)
    ca = pki.make_ca(ca_key, common_name="Shared SHC CA")
    (tmp_path / "shared.pem").write_bytes(pki.cert_pem(ca))
    (tmp_path / "shared.key").write_bytes(pki.key_pem(ca_key))
    code, out = run("issue", *HOST, "--ca-cert", str(tmp_path / "shared.pem"),
                    "--ca-key", str(tmp_path / "shared.key"))
    assert code == 0, out
    d = kvdir(splunk_home)
    assert not (d / "kvstore-ca.key").exists()
    assert (d / "kvstore-ca.pem").read_bytes() == pki.cert_pem(ca)


def test_trust_combines_and_is_stable_after_configure(run, splunk_home):
    run("issue", *HOST)
    code, out = run("trust")
    assert code == 0, out
    d = kvdir(splunk_home)
    combined = certcheck.load_certs((d / "ca-combined.pem").read_bytes())
    subjects = [c.subject.rfc4514_string() for c in combined]
    assert subjects == ["CN=Fake InCommon RSA Server CA", "CN=Splunk KV Store Internal CA"]
    first = (d / "ca-combined.pem").read_bytes()

    assert run("configure")[0] == 0
    # sslRootCAPath now points at ca-combined.pem; trust must use the recorded source.
    code, out = run("trust")
    assert code == 0, out
    assert (d / "ca-combined.pem").read_bytes() == first
    assert "is current" in out


def test_configure_edits_server_conf(run, splunk_home):
    run("issue", *HOST)
    run("trust")
    conf_path = splunk_home / "etc/system/local/server.conf"
    original = conf_path.read_text()

    code, out = run("--dry-run", "configure")
    assert code == 0 and "+serverCert =" in out
    assert conf_path.read_text() == original

    code, out = run("configure")
    assert code == 0, out
    d = kvdir(splunk_home)
    cf = ConfFile.parse(conf_path.read_text())
    assert cf.get("kvstore", "serverCert") == str(d / "kvstore-server.pem")
    assert cf.get("kvstore", "disabled") == "false"
    assert cf.get("kvstore", "sslRootCAPath") is None
    assert cf.get("kvstore", "sslVerifyServerName") is None
    assert cf.get("kvstore", "kvstoreUpgradeOnStartupEnabled") is None
    assert cf.get("sslConfig", "sslRootCAPath") == str(d / "ca-combined.pem")
    assert cf.get("sslConfig", "serverCert") == "$SPLUNK_HOME/etc/auth/server.pem"
    assert DISABLED_MARKER + "sslRootCAPath = /old/ca.pem" in conf_path.read_text()
    assert "# local settings" in conf_path.read_text()
    backups = list(conf_path.parent.glob("server.conf.bak-*"))
    assert len(backups) == 1 and backups[0].read_text() == original
    assert "[PASS] [kvstore] serverCert" in out
    assert "[PASS] [sslConfig] sslRootCAPath" in out

    code, out = run("configure")
    assert code == 0 and "already configured" in out


def test_configure_flags_override_from_another_layer(run, splunk_home):
    run("issue", *HOST)
    run("trust")
    # The fake btool lets local win, so simulate a stale value btool still reports.
    default = splunk_home / "etc/system/default/server.conf"
    default.write_text("[kvstore]\nsslVerifyServerCert = true\n")
    code, out = run("configure")
    assert code == 0
    assert "[WARN] [kvstore] sslVerifyServerCert" in out


def test_configure_requires_material(run):
    code, out = run("configure")
    assert code == 1 and "run 'issue' and 'trust' first" in out


def test_check_reports_without_fixing(run, splunk_home):
    marker = splunk_home / "var/run/splunk/kvstore_upgrade/versionFile42"
    marker.write_text("")
    (splunk_home / "var/log/splunk/splunkd.log").write_text(
        "INFO MongodRunner - Starting mongod with executable name=mongod-4.2 version=4.2\n"
    )
    code, out = run("check")
    assert code == 1
    assert "[WARN] version marker: versionFile42 present" in out
    assert "[FAIL] mongod binary" in out
    assert "[WARN] kvstoreUpgradeOnStartupEnabled" in out
    assert "sslRootCAPath (in" in out and "sslVerifyServerName (in" in out
    assert marker.exists()  # reported, never renamed


def test_check_passes_cert_checks_after_setup(run, splunk_home):
    code, out = run("setup", *HOST)
    assert code == 0, out
    assert "sudo systemctl restart Splunkd" in out
    code, out = run("check")
    cert_lines = [l for l in out.splitlines() if "] KV store cert" in l]
    assert cert_lines and all("[PASS]" in l for l in cert_lines), cert_lines
    assert "[PASS] chain" in out
    assert "[PASS] [kvstore] partial TLS settings: none" in out


def test_setup_dry_run_writes_nothing(run, splunk_home):
    conf_path = splunk_home / "etc/system/local/server.conf"
    original = conf_path.read_text()
    code, out = run("--dry-run", "setup", *HOST)
    assert code == 0, out
    assert not kvdir(splunk_home).exists()
    assert conf_path.read_text() == original
    assert "would write" in out


def test_expiry(run, splunk_home):
    assert run("expiry")[0] == 1
    run("issue", *HOST)
    code, out = run("expiry")
    assert code == 0 and "[PASS] CA" in out and "[PASS] leaf" in out
    assert run("expiry", "--warn-days", "5000")[0] == 1


@pytest.mark.skipif(os.geteuid() == 0, reason="root may write as any owner")
def test_refuses_foreign_owner(splunk_home, capsys):
    code = cli.main(["--splunk-home", str(splunk_home), "--owner", "root", "issue", *HOST])
    assert code == 2
    assert "run as root" in capsys.readouterr().err
    assert not kvdir(splunk_home).exists()
