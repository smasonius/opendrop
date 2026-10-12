# ============================================================================
# Paper:   Protocol Prying: Systematic Vulnerability Research in the Apple
#          AirDrop and Android Quick Share Proximity Transfer Protocols
# Venue:   WOOT'26 (20th USENIX WOOT Conference on Offensive Technologies)
# Authors: Arash Ale Ebrahim, Nils Ole Tippenhauer
# ============================================================================
"""
AirDrop protocol decoder — parse responses and payloads.

Used for:
  - Parsing HTTP responses from sharingd
  - Extracting plist response bodies
  - Classifying response outcomes (normal, error, crash, hang)
  - Decoding CPIO/DVZip for analysis
"""

from __future__ import annotations

import plistlib
import struct
import zlib
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Outcome(Enum):
    """Classification of a fuzz execution result."""
    NORMAL = "normal"           # Expected response (200, 401, 406, etc.)
    SERVER_ERROR = "server_error"  # 5xx response
    CRASH = "crash"             # Confirmed process crash (PID changed)
    HANG = "hang"               # Timeout waiting for response
    CONN_RESET = "conn_reset"   # Connection reset by peer
    CONN_REFUSED = "conn_refused"  # Cannot connect (not necessarily a crash)
    PARSE_ERROR = "parse_error"    # Unparseable response
    ERROR = "error"             # Transient error (Frida disconnect, etc.)
    UNEXPECTED = "unexpected"      # Something weird


@dataclass
class FuzzResponse:
    """Parsed response from target."""
    outcome: Outcome
    status: int = 0
    headers: dict = None
    body: bytes = b""
    plist: Optional[dict] = None
    elapsed_ms: float = 0.0
    error_msg: str = ""

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        # Try to parse body as plist
        if self.body and self.plist is None:
            try:
                self.plist = plistlib.loads(self.body)
            except Exception:
                pass

    @property
    def is_crash(self) -> bool:
        return self.outcome == Outcome.CRASH

    @property
    def is_hang(self) -> bool:
        return self.outcome == Outcome.HANG

    @property
    def is_error(self) -> bool:
        return self.outcome == Outcome.SERVER_ERROR or self.status >= 500

    @property
    def is_interesting(self) -> bool:
        """True if this response suggests a bug worth investigating."""
        if self.is_crash or self.is_hang:
            return True
        if self.is_error:
            return True
        if self.outcome == Outcome.UNEXPECTED:
            return True
        return False


def parse_http_response(data: bytes) -> tuple[int, dict, bytes]:
    """
    Parse raw HTTP response bytes.
    Returns (status, headers_dict, body).
    """
    if b"\r\n\r\n" not in data:
        raise ValueError("Incomplete HTTP response — no header terminator")

    hdr_end = data.index(b"\r\n\r\n") + 4
    header_section = data[:hdr_end].decode("iso-8859-1")
    body = data[hdr_end:]

    lines = header_section.split("\r\n")
    status_line = lines[0]

    # Parse status
    parts = status_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"Malformed status line: {status_line!r}")
    status = int(parts[1])

    # Parse headers
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    return status, headers, body


# ─── DVZip Decoder ────────────────────────────────────────────

def dvzip_decompress(data: bytes) -> bytes:
    """Decode DVZip format: [4-byte BE length][zlib chunk]..."""
    result = bytearray()
    off = 0
    while off + 4 <= len(data):
        chunk_len = struct.unpack(">I", data[off:off + 4])[0]
        compressed = True
        if chunk_len & 0x80000000:
            chunk_len = chunk_len&0x7fffffff
            compressed = False
        if chunk_len == 0:
            break    
        print(f"dchuck length: {chunk_len}, bytes: {data[off:off + 4]}")
        off += 4
        if off + chunk_len > len(data):
            break
        if compressed:
            try:
                result += zlib.decompress(data[off:off + chunk_len])
            except zlib.error:
                # Corrupted chunk — append raw for analysis
                print("Corrupted chunk!")
        else:
            result += data[off:off + chunk_len]
        off += chunk_len
    return bytes(result)


# ─── CPIO Decoder ─────────────────────────────────────────────

@dataclass
class CPIOEntry:
    name: str
    data: bytes
    mode: int
    size: int


def cpio_decode(data: bytes) -> list[CPIOEntry]:
    """Decode odc CPIO archive. Returns list of entries."""
    entries = []
    off = 0
    while off + 76 <= len(data):
        # odc header is 76 bytes
        magic = data[off:off + 6]
        if magic != b"070707":
            break

        # Parse header fields (all octal strings)
        try:
            mode = int(data[off + 18:off + 24], 8)
            namesize = int(data[off + 59:off + 65], 8)
            filesize = int(data[off + 65:off + 76], 8)
        except ValueError:
            break

        off += 76
        name = data[off:off + namesize].rstrip(b"\x00").decode("utf-8", errors="replace")
        off += namesize
        fdata = data[off:off + filesize]
        off += filesize

        if name == "TRAILER!!!":
            break
        print(f"Filesize: {filesize}, length: {len(fdata)}, data length: {len(data)}")
        entries.append(CPIOEntry(name=name, data=fdata, mode=mode, size=filesize))

    return entries
