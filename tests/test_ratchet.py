"""Tests for Layer 2: the braided ratchet (plexus.ratchet)."""

from __future__ import annotations

from plexus.lattice import Kem
from plexus.ratchet import BraidRatchet, Header


def _pair():
    root = b"R" * 32
    prekey = Kem.keygen()
    alice = BraidRatchet.initiator(root, prekey.public)
    bob = BraidRatchet.responder(root, prekey)
    return alice, bob


def test_header_serialize_roundtrip():
    h = Header(ratchet=True, counter=7, pub=b"P" * 10, ct=b"C" * 20)
    raw = h.serialize()
    parsed, off = Header.parse(raw)
    assert parsed.ratchet and parsed.counter == 7
    assert parsed.pub == b"P" * 10 and parsed.ct == b"C" * 20
    assert off == len(raw)

    h2 = Header(ratchet=False, counter=3)
    p2, _ = Header.parse(h2.serialize())
    assert not p2.ratchet and p2.counter == 3


def test_single_message_key_agreement():
    alice, bob = _pair()
    hdr, mk_a, seed_a = alice.send_step()
    mk_b, seed_b = bob.recv_step(hdr)
    assert mk_a == mk_b
    assert seed_a == seed_b


def test_consecutive_same_direction():
    alice, bob = _pair()
    for _ in range(5):
        hdr, mk_a, seed_a = alice.send_step()
        mk_b, seed_b = bob.recv_step(hdr)
        assert mk_a == mk_b and seed_a == seed_b


def test_turn_flips_and_self_heal():
    alice, bob = _pair()
    keys = []
    # alice -> bob
    h, mka, _ = alice.send_step(); mkb, _ = bob.recv_step(h)
    assert mka == mkb; keys.append(mka)
    # bob -> alice (turn flip -> asymmetric step on bob's side)
    h, mkb, _ = bob.send_step(); mka, _ = alice.recv_step(h)
    assert mka == mkb; keys.append(mkb)
    # alice -> bob again (another turn flip)
    h, mka, _ = alice.send_step(); mkb, _ = bob.recv_step(h)
    assert mka == mkb; keys.append(mka)
    # all message keys distinct
    assert len(set(keys)) == len(keys)
    # roots stay synchronized after healing
    assert alice.rk == bob.rk


def test_rendezvous_matches_and_rotates():
    alice, bob = _pair()
    h, _, _ = alice.send_step(); bob.recv_step(h)
    assert alice.rendezvous(b"x") == bob.rendezvous(b"x")
    assert alice.rendezvous(b"x") != alice.rendezvous(b"y")
