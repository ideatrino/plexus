"""
PLEXUS — Layer 5: the metadata skin.

  * Fixed-size CELLS: every payload is fragmented and padded to a constant cell
    size, so message length is invisible on the wire.
  * CHAFF: dummy cells, byte-indistinguishable from real ones, let a sender emit
    at a constant rate so timing and volume leak nothing.
  * RENDEZVOUS addressing: parties derive rotating, unlinkable mailbox addresses
    from shared ratchet state (see BraidRatchet.rendezvous), so an observer of an
    untrusted relay cannot link the two endpoints over time.

This module provides a minimal in-memory `Relay` so the demo and tests can run a
full exchange without a network.  A real deployment would replace `Relay` with an
untrusted store-and-forward server (and ideally a mixnet underneath).

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import os
from collections import defaultdict

from . import field

CELL_SIZE = 512
HEADER_LEN = 4          # 1 type byte + 3 length bytes
PAYLOAD_MAX = CELL_SIZE - HEADER_LEN

TYPE_DATA = 0x01
TYPE_CHAFF = 0x02


def to_cells(payload: bytes) -> list[bytes]:
    """Fragment + pad an arbitrary payload into constant-size data cells."""
    cells = []
    for off in range(0, max(len(payload), 1), PAYLOAD_MAX):
        chunk = payload[off:off + PAYLOAD_MAX]
        body = bytes([TYPE_DATA]) + len(chunk).to_bytes(3, "big") + chunk
        body += os.urandom(CELL_SIZE - len(body))   # random tail -> opaque padding
        cells.append(body)
    return cells


def chaff_cell() -> bytes:
    body = bytes([TYPE_CHAFF]) + (0).to_bytes(3, "big")
    return body + os.urandom(CELL_SIZE - len(body))


def cell_payload(cell: bytes) -> bytes | None:
    """Return the data payload of a cell, or None if it is chaff."""
    if cell[0] != TYPE_DATA:
        return None
    n = int.from_bytes(cell[1:4], "big")
    return cell[HEADER_LEN:HEADER_LEN + n]


class Relay:
    """An untrusted in-memory store-and-forward mailbox keyed by rendezvous addr."""

    def __init__(self) -> None:
        self._boxes: dict[bytes, list[bytes]] = defaultdict(list)

    def put(self, addr: bytes, cell: bytes) -> None:
        assert len(cell) == CELL_SIZE, "all cells must be the fixed size"
        self._boxes[addr].append(cell)

    def get(self, addr: bytes) -> list[bytes]:
        cells = self._boxes[addr]
        self._boxes[addr] = []
        return cells
