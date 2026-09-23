"""
Local CA and KV store leaf certificate generation.

The extensions mirror the split-certs runbook in failures.md:

* CA: ``basicConstraints=critical,CA:TRUE``, ``keyUsage=critical,keyCertSign,
  cRLSign`` and a subject key identifier. Without ``keyUsage``,
  ``openssl verify -x509_strict`` fails with error 92.
* Leaf: ``CA:FALSE``, ``keyUsage=critical,digitalSignature,keyEncipherment``,
  ``extendedKeyUsage=serverAuth,clientAuth`` (the fix for the InCommon cert),
  the SAN list, and SKI/AKI.
"""

from __future__ import annotations

import datetime
import ipaddress
from typing import Iterable, List, Optional, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DEFAULT_CA_CN = "Splunk KV Store Internal CA"
DEFAULT_DAYS = 3650
# Backdate notBefore so a small clock skew between hosts does not produce
# "error 9: certificate is not yet valid".
BACKDATE = datetime.timedelta(minutes=5)


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def new_key(bits: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _name(common_name: str, org: Optional[str]) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    return x509.Name(attrs)


def _key_usage(**enabled: bool) -> x509.KeyUsage:
    flags = dict(
        digital_signature=False,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    flags.update(enabled)
    return x509.KeyUsage(**flags)


def make_ca(
    key: rsa.RSAPrivateKey,
    common_name: str = DEFAULT_CA_CN,
    org: Optional[str] = None,
    days: int = DEFAULT_DAYS,
    now: Optional[datetime.datetime] = None,
) -> x509.Certificate:
    now = now or utcnow()
    name = _name(common_name, org)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256())
    )


def general_names(sans: Iterable[str]) -> List[x509.GeneralName]:
    """Convert normalized ``DNS:``/``IP:`` strings to x509 general names."""
    names: List[x509.GeneralName] = []
    for entry in sans:
        kind, _, value = entry.partition(":")
        if kind == "DNS":
            names.append(x509.DNSName(value))
        elif kind == "IP":
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        else:
            raise ValueError(f"unsupported SAN entry {entry!r}")
    return names


def _ca_not_after(ca_cert: x509.Certificate) -> datetime.datetime:
    value = getattr(ca_cert, "not_valid_after_utc", None)
    if value is None:
        value = ca_cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return value


def make_leaf(
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    key: rsa.RSAPrivateKey,
    common_name: str,
    sans: Sequence[str],
    org: Optional[str] = None,
    days: int = DEFAULT_DAYS,
    now: Optional[datetime.datetime] = None,
) -> x509.Certificate:
    now = now or utcnow()
    # A leaf must not outlive the CA that signed it.
    not_after = min(now + datetime.timedelta(days=days), _ca_not_after(ca_cert))
    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski.value)
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, org))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            _key_usage(digital_signature=True, key_encipherment=True), critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectAlternativeName(general_names(sans)), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(aki, critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def server_bundle(leaf: bytes, key: bytes, ca: bytes) -> bytes:
    """Splunk's documented order: server cert, private key, then the CA."""
    parts = [leaf, key, ca]
    return b"".join(p if p.endswith(b"\n") else p + b"\n" for p in parts)
