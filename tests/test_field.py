"""Tests for Layer 4: the algebraic sponge (plexus.field)."""

from __future__ import annotations

from plexus import field


def test_hash_deterministic_and_sized():
    a = field.hash(b"plexus")
    b = field.hash(b"plexus")
    assert a == b
    assert len(a) == 32
    assert len(field.hash(b"plexus", 16)) == 16
    assert len(field.hash(b"plexus", 64)) == 64


def test_hash_distinguishes_inputs():
    assert field.hash(b"alpha") != field.hash(b"beta")
    assert field.hash(b"") != field.hash(b"\x00")


def test_avalanche():
    # A one-bit input change should flip roughly half the output bits.
    a = field.hash(b"avalanche-test-vector")
    b = field.hash(b"avalanche-test-vectos")  # last byte differs by one bit region
    diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
    assert 80 < diff < 176, f"avalanche out of range: {diff}/256 bits"


def test_kdf_separation():
    key = b"k" * 32
    assert field.kdf(key, b"enc", 32) != field.kdf(key, b"mac", 32)
    assert len(field.kdf(key, b"enc", 48)) == 48


def test_mac_changes_with_data_and_key():
    assert field.mac(b"k" * 32, b"msg") != field.mac(b"k" * 32, b"msh")
    assert field.mac(b"k" * 32, b"msg") != field.mac(b"j" * 32, b"msg")


def test_prg_and_stream_lengths_and_determinism():
    assert len(field.prg(b"seed", 100)) == 100
    assert field.prg(b"seed", 100) == field.prg(b"seed", 100)
    assert len(field.stream(b"seed", 257)) == 257
    assert field.stream(b"s1", 64) != field.stream(b"s2", 64)


def test_ct_eq():
    assert field.ct_eq(b"abc", b"abc")
    assert not field.ct_eq(b"abc", b"abd")
    assert not field.ct_eq(b"abc", b"ab")
