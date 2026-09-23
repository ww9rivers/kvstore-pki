import datetime
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from kvstore_pki import certcheck, hostinfo, pki

SANS = hostinfo.default_sans("kv1.example.edu", ["10.1.2.3"])
openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl not on PATH")


@pytest.fixture(scope="module")
def material():
    ca_key = pki.new_key(2048)
    ca = pki.make_ca(ca_key, org="Test Org")
    key = pki.new_key(2048)
    leaf = pki.make_leaf(ca, ca_key, key, "kv1.example.edu", SANS, org="Test Org")
    return ca, ca_key, leaf, key


def write_files(tmp_path, material):
    ca, _, leaf, key = material
    (tmp_path / "ca.pem").write_bytes(pki.cert_pem(ca))
    (tmp_path / "leaf.crt").write_bytes(pki.cert_pem(leaf))
    (tmp_path / "leaf.key").write_bytes(pki.key_pem(key))
    bundle = pki.server_bundle(pki.cert_pem(leaf), pki.key_pem(key), pki.cert_pem(ca))
    (tmp_path / "server.pem").write_bytes(bundle)
    return tmp_path


def test_default_sans_order_and_dedupe():
    assert hostinfo.default_sans("kv1.example.edu", ["10.1.2.3"], ["dns:KV1.example.edu", "IP:10.9.9.9"]) == [
        "DNS:kv1.example.edu",
        "DNS:kv1",
        "DNS:localhost",
        "IP:10.1.2.3",
        "IP:127.0.0.1",
        "IP:10.9.9.9",
    ]


def test_bad_san_rejected():
    with pytest.raises(ValueError):
        hostinfo.normalize_san("URI:https://x")
    with pytest.raises(ValueError):
        hostinfo.normalize_san("IP:not-an-ip")


def test_ca_extensions(material):
    ca = material[0]
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage)
    assert bc.critical and bc.value.ca
    assert ku.critical and ku.value.key_cert_sign and ku.value.crl_sign
    ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    assert certcheck.ca_problems(ca) == []


def test_leaf_extensions(material):
    ca, _, leaf, key = material
    eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    ku = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    assert ku.critical and ku.value.digital_signature and ku.value.key_encipherment
    assert not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert certcheck.san_strings(leaf) == set(SANS)
    assert certcheck.purposes(leaf) == (True, True)
    assert certcheck.key_matches(leaf, key)
    assert certcheck.issued_by(leaf, ca)
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "kv1.example.edu"


def test_not_before_is_backdated(material):
    leaf = material[2]
    assert certcheck.not_before(leaf) < pki.utcnow() - datetime.timedelta(minutes=4)


def test_leaf_never_outlives_ca():
    ca_key = pki.new_key(2048)
    ca = pki.make_ca(ca_key, days=100)
    leaf = pki.make_leaf(ca, ca_key, pki.new_key(2048), "h.example", ["DNS:h.example"], days=3650)
    assert certcheck.not_after(leaf) <= certcheck.not_after(ca)


def test_bundle_order(material):
    ca, _, leaf, key = material
    bundle = pki.server_bundle(pki.cert_pem(leaf), pki.key_pem(key), pki.cert_pem(ca))
    labels = [label for label, _ in certcheck.pem_blocks(bundle)]
    assert labels == [b"CERTIFICATE", b"PRIVATE KEY", b"CERTIFICATE"]


def test_inspect_bundle_passes(material):
    ca, _, leaf, key = material
    bundle = pki.server_bundle(pki.cert_pem(leaf), pki.key_pem(key), pki.cert_pem(ca))
    results = certcheck.inspect_server_pem(bundle, pki.utcnow())
    assert not certcheck.any_failed(results), results


def test_inspect_detects_missing_key_and_server_only_eku(material):
    # Mimic the InCommon cert: serverAuth only, and the keyless -chain.crt.
    ca, ca_key, _, key = material
    now = pki.utcnow()
    incommon = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kv1.example.edu")]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=300))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    results = {r.name: r for r in certcheck.inspect_server_pem(pki.cert_pem(incommon), now)}
    assert results["private key"].status == certcheck.FAIL
    assert results["EKU"].status == certcheck.FAIL
    assert "SSL client: No" in results["EKU"].detail


def test_key_mismatch_detected(material):
    ca, _, leaf, _ = material
    other = pki.new_key(2048)
    bundle = pki.server_bundle(pki.cert_pem(leaf), pki.key_pem(other), pki.cert_pem(ca))
    results = {r.name: r for r in certcheck.inspect_server_pem(bundle, pki.utcnow())}
    assert results["key matches cert"].status == certcheck.FAIL


def ca_without_key_usage():
    key = pki.new_key(2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bare CA")])
    now = pki.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def test_error_92_in_process():
    ca, ca_key = ca_without_key_usage()
    leaf = pki.make_leaf(ca, ca_key, pki.new_key(2048), "h.example", ["DNS:h.example"])
    problems = certcheck.chain_problems(leaf, [ca], pki.utcnow())
    assert any("error 92" in p for p in problems)


def test_chain_unknown_issuer(material):
    leaf = material[2]
    other_ca = pki.make_ca(pki.new_key(2048), common_name="Other")
    problems = certcheck.chain_problems(leaf, [other_ca], pki.utcnow())
    assert any("unable to get issuer" in p for p in problems)


@openssl
def test_openssl_strict_verify_and_purpose(tmp_path, material):
    d = write_files(tmp_path, material)
    out = subprocess.run(
        ["openssl", "verify", "-verbose", "-x509_strict", "-CAfile", d / "ca.pem", d / "leaf.crt"],
        capture_output=True, text=True,
    )
    assert out.returncode == 0, out.stderr
    purpose = subprocess.run(
        ["openssl", "x509", "-noout", "-purpose", "-in", d / "server.pem"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert "SSL client : Yes" in purpose
    assert "SSL server : Yes" in purpose


@openssl
def test_openssl_rejects_ca_without_key_usage(tmp_path):
    ca, ca_key = ca_without_key_usage()
    leaf = pki.make_leaf(ca, ca_key, pki.new_key(2048), "h.example", ["DNS:h.example"])
    (tmp_path / "ca.pem").write_bytes(pki.cert_pem(ca))
    (tmp_path / "leaf.crt").write_bytes(pki.cert_pem(leaf))
    out = subprocess.run(
        ["openssl", "verify", "-x509_strict", "-CAfile", tmp_path / "ca.pem", tmp_path / "leaf.crt"],
        capture_output=True, text=True,
    )
    assert out.returncode != 0
    assert "key usage" in (out.stdout + out.stderr).lower()
