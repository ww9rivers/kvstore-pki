import os
import stat
import textwrap

import pytest

from kvstore_pki import pki

# A stand-in for $SPLUNK_HOME/bin/splunk. It answers the three commands the
# tool uses: `btool server list <stanza> --debug` (from etc/system/default
# and etc/system/local server.conf, local winning), `cmd openssl ...` (the
# system openssl), and `show kvstore-status` (canned text).
FAKE_SPLUNK = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os, re, subprocess, sys

    home = os.environ["SPLUNK_HOME"]
    args = sys.argv[1:]
    if args[:2] == ["cmd", "openssl"]:
        sys.exit(subprocess.call(["openssl", *args[2:]]))
    if args[:1] == ["show"]:
        path = os.path.join(home, "kvstore-status.txt")
        print(open(path).read() if os.path.exists(path) else "status : starting")
        sys.exit(0)
    if args[:1] == ["btool"]:
        stanza = args[3]
        merged = {}
        for layer in ("default", "local"):
            path = os.path.join(home, "etc", "system", layer, "server.conf")
            if not os.path.exists(path):
                continue
            current = None
            for line in open(path):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r"^\\[(.*)\\]$", line)
                if m:
                    current = m.group(1)
                    continue
                if current == stanza and "=" in line:
                    k, v = line.split("=", 1)
                    merged[k.strip()] = (v.strip(), path)
        local = os.path.join(home, "etc", "system", "local", "server.conf")
        print(f"{local} [{stanza}]")
        for k, (v, path) in merged.items():
            print(f"{path} {k} = {v}")
        sys.exit(0)
    sys.exit(f"fake splunk: unsupported {args}")
    """
)


@pytest.fixture
def splunk_home(tmp_path):
    home = tmp_path / "splunk"
    for d in ("bin", "etc/system/local", "etc/system/default", "etc/auth",
              "var/log/splunk", "var/run/splunk/kvstore_upgrade"):
        (home / d).mkdir(parents=True)
    splunk = home / "bin" / "splunk"
    splunk.write_text(FAKE_SPLUNK)
    splunk.chmod(splunk.stat().st_mode | stat.S_IXUSR)
    # A stand-in for the InCommon chain that sslRootCAPath points at.
    ca_key = pki.new_key(2048)
    ca = pki.make_ca(ca_key, common_name="Fake InCommon RSA Server CA")
    (home / "etc/auth/incommon-ca.cer").write_bytes(pki.cert_pem(ca))
    os.symlink(home / "etc/auth/incommon-ca.cer", home / "etc/auth/cacert.pem")
    (home / "etc/system/local/server.conf").write_text(
        textwrap.dedent(
            f"""\
            # local settings
            [sslConfig]
            serverCert = $SPLUNK_HOME/etc/auth/server.pem
            sslRootCAPath = {home}/etc/auth/cacert.pem

            [kvstore]
            # legacy
            sslRootCAPath = /old/ca.pem
            sslVerifyServerName = false
            """
        )
    )
    return home


@pytest.fixture
def owner():
    import pwd

    return pwd.getpwuid(os.geteuid()).pw_name
