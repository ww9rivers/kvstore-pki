"""
Line-based editor for Splunk ``.conf`` files.

``configparser`` is not used: it drops comments, rejects duplicate keys, and
mishandles Splunk's backslash continuation lines. This editor keeps every
line it does not touch byte-for-byte, so parse + render with no edits
round-trips exactly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

_STANZA = re.compile(r"^\s*\[(?P<name>[^\]]*)\]\s*$")
_KEY = re.compile(r"^\s*(?P<key>[^#\s=\[][^=]*?)\s*=\s*(?P<value>.*?)\s*$", re.S)

DISABLED_MARKER = "# kvstore-pki: disabled: "


@dataclass
class Entry:
    kind: str  # "stanza", "kv", or "other" (comments, blanks)
    stanza: str  # "" for lines before the first stanza header
    text: str  # physical line(s), including line endings
    key: Optional[str] = None

    @property
    def value(self) -> str:
        m = _KEY.match(self.text.rstrip("\r\n"))
        return m.group("value") if m else ""


def _eol(text: str) -> str:
    if text.endswith("\r\n"):
        return "\r\n"
    return "\n"


class ConfFile:
    def __init__(self, entries: List[Entry]):
        self.entries = entries

    @classmethod
    def parse(cls, text: str) -> "ConfFile":
        entries: List[Entry] = []
        stanza = ""
        lines = text.splitlines(keepends=True)
        i = 0
        while i < len(lines):
            line = lines[i]
            bare = line.rstrip("\r\n")
            m = _STANZA.match(bare)
            if m:
                stanza = m.group("name")
                entries.append(Entry("stanza", stanza, line))
                i += 1
                continue
            m = _KEY.match(bare)
            if m and not bare.lstrip().startswith("#"):
                text_block = line
                # A trailing backslash continues the value on the next line.
                while text_block.rstrip("\r\n").endswith("\\") and i + 1 < len(lines):
                    i += 1
                    text_block += lines[i]
                entries.append(Entry("kv", stanza, text_block, m.group("key")))
            else:
                entries.append(Entry("other", stanza, line))
            i += 1
        return cls(entries)

    def render(self) -> str:
        return "".join(e.text for e in self.entries)

    def _kv(self, stanza: str, key: str) -> List[int]:
        return [
            i
            for i, e in enumerate(self.entries)
            if e.kind == "kv" and e.stanza == stanza and e.key == key
        ]

    def has_stanza(self, stanza: str) -> bool:
        return any(e.kind == "stanza" and e.stanza == stanza for e in self.entries)

    def get(self, stanza: str, key: str) -> Optional[str]:
        """Return the effective value; the last occurrence wins, as in Splunk."""
        idx = self._kv(stanza, key)
        return self.entries[idx[-1]].value if idx else None

    def set(self, stanza: str, key: str, value: str) -> bool:
        """Set ``key`` in ``stanza``. Returns True if the file changed."""
        before = self.render()
        idx = self._kv(stanza, key)
        if idx:
            first = self.entries[idx[0]]
            first.text = f"{key} = {value}{_eol(first.text)}"
            for i in idx[1:]:
                self._disable(self.entries[i])
        else:
            self._insert(stanza, Entry("kv", stanza, f"{key} = {value}\n", key))
        return self.render() != before

    def comment_out(self, stanza: str, key: str) -> int:
        """Comment out every occurrence of ``key`` in ``stanza``; return the count."""
        idx = self._kv(stanza, key)
        for i in idx:
            self._disable(self.entries[i])
        return len(idx)

    @staticmethod
    def _disable(entry: Entry) -> None:
        lines = entry.text.splitlines(keepends=True)
        entry.text = "".join(DISABLED_MARKER + line for line in lines)
        entry.kind = "other"
        entry.key = None

    def _insert(self, stanza: str, new: Entry) -> None:
        positions = [i for i, e in enumerate(self.entries) if e.stanza == stanza]
        header = next(
            (i for i in positions if self.entries[i].kind == "stanza"), None
        )
        if header is None:
            if self.entries and not self.entries[-1].text.endswith(("\n", "\r\n")):
                self.entries[-1].text += "\n"
            if self.entries and self.entries[-1].text.strip():
                self.entries.append(Entry("other", stanza, "\n"))
            self.entries.append(Entry("stanza", stanza, f"[{stanza}]\n"))
            self.entries.append(new)
            return
        # Insert after the last key in the stanza, or right after its header.
        # The stanza's own block ends at the next header.
        end = header
        for i in range(header + 1, len(self.entries)):
            if self.entries[i].kind == "stanza":
                break
            if self.entries[i].kind == "kv":
                end = i
        prev = self.entries[end]
        if not prev.text.endswith(("\n", "\r\n")):
            prev.text += "\n"
        self.entries.insert(end + 1, new)
