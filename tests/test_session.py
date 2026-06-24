"""End-to-end tests for the high-level Session (plexus.session)."""

from __future__ import annotations

import os

from plexus.cells import Relay
from plexus.session import AuthenticationError, Session


def test_establish_agrees_on_sas():
    alice, bob, sas = Session.establish()
    assert isinstance(sas, str) and len(sas.replace(" ", "")) == 7


def test_direct_encrypt_decrypt():
    alice, bob, _ = Session.establish()
    msg = b"the quick brown fox"
    assert bob.decrypt(alice.encrypt(msg)) == msg


def test_full_duplex_through_relay_with_turn_flips():
    alice, bob, _ = Session.establish()
    relay = Relay()

    # A -> B twice (same direction)
    for m in (b"hello bob", b"still alice here"):
        alice.send(m, relay, n_chaff=2)
        assert bob.receive(relay) == m

    # B -> A twice (turn flip triggers asymmetric heal)
    for m in (b"hi alice", b"bob again"):
        bob.send(m, relay)
        assert alice.receive(relay) == m

    # A -> B once more (another flip)
    alice.send(b"final", relay)
    assert bob.receive(relay) == b"final"

    assert alice.ratchet.rk == bob.ratchet.rk


def test_multi_cell_payload():
    alice, bob, _ = Session.establish()
    relay = Relay()
    big = os.urandom(1500)
    alice.send(big, relay, n_chaff=3)
    assert bob.receive(relay) == big


def test_tamper_is_rejected():
    alice, bob, _ = Session.establish()
    wire = bytearray(alice.encrypt(b"authentic"))
    wire[-1] ^= 0x01
    try:
        bob.decrypt(bytes(wire))
        assert False, "tamper not detected"
    except AuthenticationError:
        pass


def test_true_otp_budget_consumed():
    shared = os.urandom(64)
    alice, bob, _ = Session.establish(true_entropy_a2b=shared)
    assert alice.pool_send.true_entropy_remaining == 64
    alice.encrypt(b"x" * 40)
    assert alice.pool_send.true_entropy_remaining == 24


def test_chaff_does_not_corrupt_payload():
    alice, bob, _ = Session.establish()
    relay = Relay()
    alice.send(b"payload with lots of chaff", relay, n_chaff=10)
    assert bob.receive(relay) == b"payload with lots of chaff"
