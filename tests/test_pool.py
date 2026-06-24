"""Tests for Layer 3: the entropy pool (plexus.pool)."""

from __future__ import annotations

import os

from plexus.pool import EntropyPool


def test_mirror_pools_agree():
    a = EntropyPool(label=b"A2B")
    b = EntropyPool(label=b"A2B")
    for _ in range(4):
        seed = os.urandom(32)
        a.absorb(seed)
        b.absorb(seed)
        assert a.pad(50) == b.pad(50)


def test_pad_never_repeats_positions():
    a = EntropyPool(label=b"dir")
    a.absorb(b"s" * 32)
    first = a.pad(64)
    second = a.pad(64)
    assert first != second  # never-rewound counter


def test_true_entropy_consumed_first():
    shared = os.urandom(48)
    a = EntropyPool(label=b"dir", true_entropy=shared)
    assert a.true_entropy_remaining == 48
    out = a.pad(20)
    assert out == shared[:20]               # info-theoretic bytes used verbatim
    assert a.true_entropy_remaining == 28


def test_true_entropy_falls_back_to_stream():
    shared = os.urandom(16)
    a = EntropyPool(label=b"dir", true_entropy=shared)
    out = a.pad(40)                          # 16 true + 24 computational
    assert out[:16] == shared
    assert len(out) == 40
    assert a.true_entropy_remaining == 0


def test_labels_separate_streams():
    a = EntropyPool(label=b"A2B")
    b = EntropyPool(label=b"B2A")
    assert a.pad(32) != b.pad(32)
