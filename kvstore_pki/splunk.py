"""
Access to a Splunk installation: btool, bundled OpenSSL, logs, and liveness.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

DEFAULT_HOMES = ("/app/splunk", "/opt/splunk")
KVSTORE_PORT = 8191


class SplunkError(Exception):
    pass


@dataclass
class Setting:
    value: str
    file: str


_BTOOL_LINE = re.compile(r"^(?P<file>\S+)\s+(?P<content>.*)$")
_BTOOL_KV = re.compile(r"^(?P<key>[^=\s][^=]*?)\s*=\s*(?P<value>.*)$")
_MONGOD_EXE = re.compile(r"Starting mongod with executable name=(?P<name>\S+)")


def find_home(explicit: Optional[str] = None) -> str:
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("SPLUNK_HOME")
    if env:
        return os.path.abspath(env)
    for home in DEFAULT_HOMES:
        if os.path.isdir(home):
            return home
    raise SplunkError("cannot find SPLUNK_HOME; pass --splunk-home")


def parse_btool(output: str, stanza: str) -> Dict[str, Setting]:
    """Parse ``btool <conf> list <stanza> --debug`` output into key -> Setting."""
    settings: Dict[str, Setting] = {}
    current = None
    for line in output.splitlines():
        m = _BTOOL_LINE.match(line)
        if not m:
            continue
        content = m.group("content").strip()
        if content.startswith("[") and content.endswith("]"):
            current = content[1:-1]
            continue
        if current != stanza:
            continue
        kv = _BTOOL_KV.match(content)
        if kv:
            settings[kv.group("key")] = Setting(kv.group("value").strip(), m.group("file"))
    return settings


class Splunk:
    def __init__(self, home: str):
        self.home = home

    def path(self, *parts: str) -> str:
        return os.path.join(self.home, *parts)

    @property
    def binary(self) -> str:
        return self.path("bin", "splunk")

    @property
    def local_server_conf(self) -> str:
        return self.path("etc", "system", "local", "server.conf")

    @property
    def default_dir(self) -> str:
        return self.path("etc", "auth", "kvstore")

    def expand(self, value: str) -> str:
        return value.replace("${SPLUNK_HOME}", self.home).replace("$SPLUNK_HOME", self.home)

    def run(self, args: Sequence[str], timeout: int = 120) -> subprocess.CompletedProcess:
        if not os.access(self.binary, os.X_OK):
            raise SplunkError(f"{self.binary} not found or not executable")
        env = dict(os.environ, SPLUNK_HOME=self.home)
        return subprocess.run(
            [self.binary, *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout,
        )

    def btool(self, conf: str, stanza: str) -> Dict[str, Setting]:
        proc = self.run(["btool", conf, "list", stanza, "--debug"])
        if proc.returncode != 0:
            raise SplunkError(f"btool {conf} list {stanza} failed: {proc.stderr.strip()}")
        return parse_btool(proc.stdout, stanza)

    def setting(self, stanza: str, key: str, default: Optional[str] = None) -> Optional[str]:
        found = self.btool("server", stanza).get(key)
        return found.value if found else default

    def openssl(self, args: Sequence[str]) -> "OpenSSLResult":
        """Run Splunk's bundled OpenSSL, falling back to the system one."""
        if os.access(self.binary, os.X_OK):
            proc = self.run(["cmd", "openssl", *args])
            return OpenSSLResult(proc, bundled=True)
        system = shutil.which("openssl")
        if system is None:
            raise SplunkError("neither splunk nor openssl is available")
        proc = subprocess.run([system, *args], capture_output=True, text=True, timeout=60)
        return OpenSSLResult(proc, bundled=False)

    def kvstore_status(self, auth: str) -> subprocess.CompletedProcess:
        return self.run(["show", "kvstore-status", "-auth", auth])

    # -- logs and state ------------------------------------------------------

    def log(self, name: str) -> str:
        return self.path("var", "log", "splunk", name)

    def read_log(self, name: str) -> Optional[str]:
        try:
            with open(self.log(name), "r", errors="replace") as fh:
                return fh.read()
        except FileNotFoundError:
            return None

    def boot_time(self) -> Optional[float]:
        """splunkd's start time, taken from the pid file's mtime."""
        try:
            return os.stat(self.path("var", "run", "splunk", "splunkd.pid")).st_mtime
        except FileNotFoundError:
            return None

    def version_markers(self) -> List[str]:
        directory = self.path("var", "run", "splunk", "kvstore_upgrade")
        try:
            return sorted(n for n in os.listdir(directory) if n.startswith("versionFile"))
        except FileNotFoundError:
            return []

    def mongod_executable(self) -> Optional[str]:
        """The mongod binary name splunkd last tried to start, from splunkd.log."""
        text = self.read_log("splunkd.log") or ""
        names = _MONGOD_EXE.findall(text)
        return names[-1] if names else None

    def since_last_start(self, text: str) -> str:
        """The part of splunkd.log after the most recent ``Splunkd starting``."""
        idx = text.rfind("Splunkd starting")
        return text[idx:] if idx >= 0 else text


@dataclass
class OpenSSLResult:
    proc: subprocess.CompletedProcess
    bundled: bool

    @property
    def ok(self) -> bool:
        return self.proc.returncode == 0

    @property
    def output(self) -> str:
        return self.proc.stdout + self.proc.stderr

    @property
    def label(self) -> str:
        return "splunk cmd openssl" if self.bundled else "system openssl"


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def mongod_running() -> bool:
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm") as fh:
                if fh.read().strip().startswith("mongod"):
                    return True
        except OSError:
            continue
    return False
