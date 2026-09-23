"""
Host name and address discovery for the KV store certificate SAN.

The certificate certifies the host FQDN, its short name, its non-loopback
IPv4 addresses, ``localhost``, and ``127.0.0.1``. splunkd does not validate
host names on the loopback connection, but listing them removes the question.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, List, Optional


class HostError(Exception):
    pass


def discover_fqdn() -> str:
    fqdn = socket.getfqdn()
    if "." not in fqdn:
        raise HostError(
            f"hostname {fqdn!r} is not fully qualified; pass --hostname explicitly"
        )
    return fqdn.lower()


def discover_ips(fqdn: str) -> List[str]:
    """Return the non-loopback IPv4 addresses ``fqdn`` resolves to, sorted."""
    try:
        infos = socket.getaddrinfo(fqdn, None, socket.AF_INET)
    except socket.gaierror:
        return []
    ips = {info[4][0] for info in infos}
    return sorted(
        (ip for ip in ips if not ipaddress.ip_address(ip).is_loopback),
        key=ipaddress.ip_address,
    )


def normalize_san(entry: str) -> str:
    """Canonicalize a ``DNS:name`` or ``IP:address`` entry."""
    kind, sep, value = entry.partition(":")
    kind = kind.strip().upper()
    value = value.strip()
    if not sep or not value:
        raise ValueError(f"SAN entry {entry!r} must look like DNS:name or IP:address")
    if kind == "DNS":
        return f"DNS:{value.lower()}"
    if kind == "IP":
        return f"IP:{ipaddress.ip_address(value)}"
    raise ValueError(f"SAN entry {entry!r}: type must be DNS or IP")


def default_sans(
    fqdn: str, ips: Iterable[str] = (), extra: Iterable[str] = ()
) -> List[str]:
    """Build the ordered, de-duplicated SAN list for the KV store certificate."""
    short = fqdn.split(".", 1)[0]
    entries = [f"DNS:{fqdn}", f"DNS:{short}", "DNS:localhost"]
    entries += [f"IP:{ip}" for ip in ips]
    entries.append("IP:127.0.0.1")
    entries += list(extra)
    seen: List[str] = []
    for entry in entries:
        norm = normalize_san(entry)
        if norm not in seen:
            seen.append(norm)
    return seen


def host_sans(
    hostname: Optional[str], extra: Iterable[str] = (), resolve: bool = True
) -> List[str]:
    fqdn = hostname.lower() if hostname else discover_fqdn()
    ips = discover_ips(fqdn) if resolve else []
    return default_sans(fqdn, ips, extra)
