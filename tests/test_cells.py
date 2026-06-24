"""Tests for Layer 5: cells, chaff and the relay (plexus.cells)."""

from __future__ import annotations

import os

from plexus import cells


def test_cells_are_fixed_size():
    for n in (0, 1, 500, 508, 509, 2000):
        for cell in cells.to_cells(os.urandom(n)):
            assert len(cell) == cells.CELL_SIZE


def test_roundtrip_reassembly():
    payload = os.urandom(1700)
    chunks = cells.to_cells(payload)
    out = b"".join(
        cells.cell_payload(c) for c in chunks if cells.cell_payload(c) is not None
    )
    assert out == payload


def test_chaff_is_dropped_and_fixed_size():
    c = cells.chaff_cell()
    assert len(c) == cells.CELL_SIZE
    assert cells.cell_payload(c) is None


def test_chaff_indistinguishable_size():
    data = cells.to_cells(os.urandom(100))[0]
    chaff = cells.chaff_cell()
    assert len(data) == len(chaff) == cells.CELL_SIZE


def test_relay_store_and_forward():
    relay = cells.Relay()
    addr = b"a" * 16
    relay.put(addr, cells.chaff_cell())
    relay.put(addr, cells.chaff_cell())
    got = relay.get(addr)
    assert len(got) == 2
    assert relay.get(addr) == []   # drained after read
