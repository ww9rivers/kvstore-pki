import textwrap

from kvstore_pki.conf import DISABLED_MARKER, ConfFile

SAMPLE = textwrap.dedent(
    """\
    # top comment
    serverName = before-any-stanza

    [general]
    serverName = kv1   
    pass4SymmKey = $7$abc

    [sslConfig]
    # InCommon on 8089
    serverCert = /app/splunk/etc/auth/server.pem
    sslRootCAPath = /app/splunk/etc/auth/cacert.pem

    [kvstore]
    sslRootCAPath = /old/ca.pem
    port = 8191
    cipherSuite = ECDHE-RSA-AES256-GCM-SHA384:\\
    ECDHE-RSA-AES128-GCM-SHA256
    # trailing comment in kvstore
    """
)


def test_round_trip_is_exact():
    assert ConfFile.parse(SAMPLE).render() == SAMPLE


def test_round_trip_crlf_and_no_final_newline():
    text = "[a]\r\nx = 1\r\n# c\r\ny = 2"
    assert ConfFile.parse(text).render() == text


def test_get_and_continuation():
    cf = ConfFile.parse(SAMPLE)
    assert cf.get("general", "serverName") == "kv1"
    assert cf.get("", "serverName") == "before-any-stanza"
    assert cf.get("kvstore", "port") == "8191"
    assert "ECDHE-RSA-AES128" in cf.get("kvstore", "cipherSuite")
    assert cf.get("kvstore", "missing") is None


def test_set_replaces_in_place():
    cf = ConfFile.parse(SAMPLE)
    assert cf.set("sslConfig", "sslRootCAPath", "/new/ca-combined.pem")
    out = cf.render()
    assert "sslRootCAPath = /new/ca-combined.pem\n" in out
    assert "/app/splunk/etc/auth/cacert.pem" not in out
    assert "# InCommon on 8089" in out
    assert out.index("serverCert =") < out.index("sslRootCAPath = /new")


def test_set_unchanged_returns_false():
    cf = ConfFile.parse(SAMPLE)
    assert not cf.set("kvstore", "port", "8191")
    assert cf.render() == SAMPLE


def test_set_appends_after_last_key_in_stanza():
    cf = ConfFile.parse(SAMPLE)
    cf.set("kvstore", "serverCert", "/x/kvstore-server.pem")
    lines = cf.render().splitlines()
    i = lines.index("serverCert = /x/kvstore-server.pem")
    assert lines[i - 1] == "ECDHE-RSA-AES128-GCM-SHA256"  # after the continuation
    assert lines[i + 1] == "# trailing comment in kvstore"


def test_set_into_middle_stanza_stays_in_stanza():
    cf = ConfFile.parse(SAMPLE)
    cf.set("general", "site", "site1")
    out = cf.render()
    assert out.index("site = site1") < out.index("[sslConfig]")


def test_set_creates_missing_stanza():
    cf = ConfFile.parse("[general]\nserverName = kv1")
    cf.set("kvstore", "disabled", "false")
    assert cf.render() == "[general]\nserverName = kv1\n\n[kvstore]\ndisabled = false\n"


def test_set_on_empty_file():
    cf = ConfFile.parse("")
    cf.set("kvstore", "disabled", "false")
    assert cf.render() == "[kvstore]\ndisabled = false\n"


def test_comment_out_including_continuation():
    cf = ConfFile.parse(SAMPLE)
    assert cf.comment_out("kvstore", "cipherSuite") == 1
    assert cf.comment_out("kvstore", "nothing") == 0
    out = cf.render()
    assert DISABLED_MARKER + "cipherSuite = ECDHE" in out
    assert DISABLED_MARKER + "ECDHE-RSA-AES128-GCM-SHA256" in out
    assert cf.get("kvstore", "cipherSuite") is None
    # Only the [kvstore] copy is touched.
    assert ConfFile.parse(out).get("sslConfig", "sslRootCAPath") == "/app/splunk/etc/auth/cacert.pem"


def test_duplicate_keys_collapse_to_one():
    cf = ConfFile.parse("[kvstore]\nserverCert = a\nserverCert = b\n")
    assert cf.get("kvstore", "serverCert") == "b"  # last wins, as in Splunk
    cf.set("kvstore", "serverCert", "c")
    assert cf.render() == f"[kvstore]\nserverCert = c\n{DISABLED_MARKER}serverCert = b\n"
