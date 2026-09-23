"""
Inspection of existing PEM material.

These are the in-process equivalents of the runbook checks: private key
present, key matches cert, both SSL purposes, clean chain, nothing expired.
"""

from __future__ import annotations

import datetime
import hashlib
import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Set, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"

_PEM_BLOCK = re.compile(
    rb"-----BEGIN (?P<label>[A-Z0-9 ]+)-----\r?\n.*?-----END (?P=label)-----\r?\n?",
    re.S,
)
PRIVATE_KEY_LABEL = re.compile(rb"^(?:[A-Z0-9]+ )?(?:ENCRYPTED )?PRIVATE KEY$")


@dataclass
class Result:
    status: str
    name: str
    detail: str = ""

    def __str__(self) -> str:
        text = f"[{self.status}] {self.name}"
        return f"{text}: {self.detail}" if self.detail else text


def any_failed(results: Sequence[Result]) -> bool:
    return any(r.status == FAIL for r in results)


def pem_blocks(data: bytes) -> List[Tuple[bytes, bytes]]:
    """Return (label, block) for every PEM block in ``data``."""
    return [(m.group("label"), m.group(0)) for m in _PEM_BLOCK.finditer(data)]


def load_certs(data: bytes) -> List[x509.Certificate]:
    return [
        x509.load_pem_x509_certificate(block)
        for label, block in pem_blocks(data)
        if label in (b"CERTIFICATE", b"TRUSTED CERTIFICATE")
    ]


def private_key_blocks(data: bytes) -> List[bytes]:
    return [block for label, block in pem_blocks(data) if PRIVATE_KEY_LABEL.match(label)]


def is_encrypted_key(block: bytes) -> bool:
    return b"ENCRYPTED PRIVATE KEY" in block or b"Proc-Type: 4,ENCRYPTED" in block


def load_private_key(data: bytes):
    """Load the first private key in ``data``; None if there is no key block."""
    blocks = private_key_blocks(data)
    if not blocks:
        return None
    return serialization.load_pem_private_key(blocks[0], password=None)


def _spki(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def key_matches(cert: x509.Certificate, key) -> bool:
    return _spki(cert.public_key()) == _spki(key.public_key())


def fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def not_before(cert: x509.Certificate) -> datetime.datetime:
    value = getattr(cert, "not_valid_before_utc", None)
    if value is None:
        value = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    return value


def not_after(cert: x509.Certificate) -> datetime.datetime:
    value = getattr(cert, "not_valid_after_utc", None)
    if value is None:
        value = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return value


def _ext(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except x509.ExtensionNotFound:
        return None


def purposes(cert: x509.Certificate) -> Tuple[bool, bool]:
    """
    Return (ssl_server, ssl_client) the way ``openssl x509 -purpose`` judges them.

    No EKU extension means the certificate is unrestricted. A keyUsage
    extension, when present, must also allow the handshake.
    """
    eku = _ext(cert, x509.ExtendedKeyUsage)
    if eku is None:
        server = client = True
    else:
        anyeku = ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE in eku
        server = anyeku or ExtendedKeyUsageOID.SERVER_AUTH in eku
        client = anyeku or ExtendedKeyUsageOID.CLIENT_AUTH in eku
    ku = _ext(cert, x509.KeyUsage)
    if ku is not None:
        server = server and (ku.digital_signature or ku.key_encipherment)
        client = client and ku.digital_signature
    return server, client


def san_strings(cert: x509.Certificate) -> Set[str]:
    san = _ext(cert, x509.SubjectAlternativeName)
    if san is None:
        return set()
    names = {f"DNS:{n.lower()}" for n in san.get_values_for_type(x509.DNSName)}
    names |= {f"IP:{ip}" for ip in san.get_values_for_type(x509.IPAddress)}
    return names


def ca_problems(cert: x509.Certificate) -> List[str]:
    """Reasons ``cert`` cannot act as a CA under ``openssl verify -x509_strict``."""
    problems = []
    bc = _ext(cert, x509.BasicConstraints)
    if bc is None or not bc.ca:
        problems.append("basicConstraints does not assert CA:TRUE")
    ku = _ext(cert, x509.KeyUsage)
    if ku is None:
        problems.append(
            "CA cert does not include key usage extension (openssl error 92)"
        )
    elif not ku.key_cert_sign:
        problems.append("CA keyUsage does not include keyCertSign")
    return problems


def validity_problems(
    cert: x509.Certificate, now: datetime.datetime, what: str = "certificate"
) -> List[str]:
    if now < not_before(cert):
        return [f"{what} is not yet valid (notBefore {not_before(cert):%Y-%m-%d %H:%M} UTC)"]
    if now > not_after(cert):
        return [f"{what} expired {not_after(cert):%Y-%m-%d}"]
    return []


def days_left(cert: x509.Certificate, now: datetime.datetime) -> int:
    return (not_after(cert) - now).days


def issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    if cert.issuer != issuer.subject:
        return False
    try:
        cert.verify_directly_issued_by(issuer)
    except Exception:  # signature mismatch, unsupported key type
        return False
    return True


def chain_problems(
    leaf: x509.Certificate,
    trust: Sequence[x509.Certificate],
    now: datetime.datetime,
) -> List[str]:
    """Walk from ``leaf`` to a self-signed root found in ``trust``."""
    problems = validity_problems(leaf, now, "leaf")
    current = leaf
    for depth in range(1, 10):
        issuer = next((c for c in trust if issued_by(current, c)), None)
        if issuer is None:
            problems.append(
                f"unable to get issuer certificate at depth {depth} "
                f"({current.issuer.rfc4514_string()})"
            )
            return problems
        who = f"CA at depth {depth} ({issuer.subject.rfc4514_string()})"
        problems += [f"{who}: {p}" for p in ca_problems(issuer)]
        problems += validity_problems(issuer, now, who)
        if issuer.subject == issuer.issuer:
            return problems
        current = issuer
    problems.append("chain is too long")
    return problems


def inspect_server_pem(data: bytes, now: datetime.datetime) -> List[Result]:
    """Run the key/EKU/expiry checks on a combined server PEM."""
    results: List[Result] = []
    certs = load_certs(data)
    if not certs:
        return [Result(FAIL, "certificate", "no CERTIFICATE block found")]
    leaf = certs[0]
    results.append(Result(PASS, "subject", leaf.subject.rfc4514_string()))

    blocks = private_key_blocks(data)
    if not blocks:
        results.append(
            Result(FAIL, "private key", "none in PEM; mongod exits at startup (failures.md §0)")
        )
    elif is_encrypted_key(blocks[0]):
        results.append(Result(WARN, "private key", "present but encrypted; key match not checked"))
    else:
        results.append(Result(PASS, "private key", "present"))
        key = serialization.load_pem_private_key(blocks[0], password=None)
        if key_matches(leaf, key):
            results.append(Result(PASS, "key matches cert"))
        else:
            results.append(Result(FAIL, "key matches cert", "private key belongs to a different cert"))

    server, client = purposes(leaf)
    detail = f"SSL server: {'Yes' if server else 'No'}, SSL client: {'Yes' if client else 'No'}"
    if server and client:
        results.append(Result(PASS, "EKU", detail))
    else:
        results.append(
            Result(FAIL, "EKU", detail + "; KV store needs serverAuth + clientAuth (failures.md §2)")
        )

    expired = [p for c in certs for p in validity_problems(c, now, c.subject.rfc4514_string())]
    if expired:
        results += [Result(FAIL, "validity", p) for p in expired]
    else:
        results.append(Result(PASS, "validity", f"leaf expires {not_after(leaf):%Y-%m-%d}"))
    return results


def describe(cert: Optional[x509.Certificate]) -> str:
    if cert is None:
        return "-"
    return f"{cert.subject.rfc4514_string()} (expires {not_after(cert):%Y-%m-%d})"
