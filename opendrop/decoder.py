# This file was originally taken from:
# 
# ============================================================================
# Paper:   Protocol Prying: Systematic Vulnerability Research in the Apple
#          AirDrop and Android Quick Share Proximity Transfer Protocols
# Venue:   WOOT'26 (20th USENIX WOOT Conference on Offensive Technologies)
# Authors: Arash Ale Ebrahim, Nils Ole Tippenhauer
# ============================================================================
#
# Unused functions were removed and support for uncompressed chunks in the decompressor was added.
"""
AirDrop protocol decoder — parse responses and payloads.

Used for decoding CPIO/DVZip for analysis
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

# ─── Chunked reader ────────────────────────────────────────────

def read_chunked(rfile):
    body = bytearray()
    while True:
        # Chunk size line, e.g. b"1a\r\n"
        line = rfile.readline()
        if not line:
            raise ConnectionError("Unexpected EOF")

        size = int(line.split(b";", 1)[0], 16)

        if size == 0:
            # Consume trailing headers until the empty line.
            while True:
                line = rfile.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
            break

        chunk = rfile.read(size)
        if len(chunk) != size:
            raise ConnectionError("Unexpected EOF in chunk")

        body.extend(chunk)

        # Consume the chunk's trailing CRLF.
        crlf = rfile.read(2)
        if crlf != b"\r\n":
            raise ValueError("Invalid chunk terminator")

    return bytes(body)

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
