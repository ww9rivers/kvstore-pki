"""
Filesystem helpers: atomic writes with exact modes, ownership, and backups.

Every file the tool produces is written to a temporary file in the target
directory and moved into place with ``os.replace``, so splunkd never sees a
half-written PEM or ``server.conf``.
"""

from __future__ import annotations

import datetime
import os
import pwd
import shutil
import tempfile
from typing import Optional, Tuple

Ids = Tuple[int, int]


class OwnerError(Exception):
    """The current user cannot produce files owned by the requested owner."""


def resolve_owner(name: str) -> Optional[Ids]:
    """
    Return the (uid, gid) files must be chowned to, or None if no chown is needed.

    Root may write on behalf of any user. A non-root user may only write as
    itself; anything else would leave files that splunkd cannot read.
    """
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        raise OwnerError(f"owner user {name!r} does not exist") from None
    euid = os.geteuid()
    if euid == 0:
        return (pw.pw_uid, pw.pw_gid)
    if euid == pw.pw_uid:
        return None
    raise OwnerError(f"run as root or as {name!r} (currently uid {euid})")


def ensure_dir(path: str, mode: int = 0o700, ids: Optional[Ids] = None) -> None:
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    if ids is not None:
        os.chown(path, *ids)


def write_file(path: str, data: bytes, mode: int, ids: Optional[Ids] = None) -> None:
    """Atomically write ``data`` to ``path`` with exactly ``mode``."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".kvstore-pki-")
    try:
        with os.fdopen(fd, "wb") as fh:
            os.fchmod(fh.fileno(), mode)
            if ids is not None:
                os.fchown(fh.fileno(), *ids)
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def replace_preserving(path: str, data: bytes) -> None:
    """Atomically replace an existing file, keeping its mode and ownership."""
    st = os.stat(path)
    ids = (st.st_uid, st.st_gid) if os.geteuid() == 0 else None
    write_file(path, data, st.st_mode & 0o7777, ids)


def read_file(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read()


def read_optional(path: str) -> Optional[bytes]:
    try:
        return read_file(path)
    except FileNotFoundError:
        return None


def backup(path: str, now: Optional[datetime.datetime] = None) -> str:
    """Copy ``path`` to ``path.bak-YYYYmmdd-HHMMSS`` and return the backup path."""
    now = now or datetime.datetime.now()
    dest = f"{path}.bak-{now:%Y%m%d-%H%M%S}"
    shutil.copy2(path, dest)
    return dest
