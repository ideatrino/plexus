"""Tests for Layer 6: handshake, SAS and deniability (plexus.identity)."""

from __future__ import annotations

from plexus import identity


def _handshake():
    a_id = identity.gen_identity()
    b_id = identity.gen_identity()
    b_prekey = identity.gen_identity()
    ss1, hello = identity.initiator_begin(a_id, b_id.public)
    root_b, sas_b, accept = identity.responder_accept(b_id, b_prekey, hello)
    root_a, sas_a = identity.initiator_finish(a_id, ss1, hello, accept)
    return root_a, root_b, sas_a, sas_b


def test_handshake_root_agreement():
    root_a, root_b, _, _ = _handshake()
    assert root_a == root_b
    assert len(root_a) == 32


def test_sas_agreement_and_format():
    _, _, sas_a, sas_b = _handshake()
    assert sas_a == sas_b
    parts = sas_a.split(" ")
    assert [len(p) for p in parts] == [3, 2, 2]
    assert all(p.isdigit() for p in parts)


def test_distinct_sessions_differ():
    r1a, _, s1, _ = _handshake()
    r2a, _, s2, _ = _handshake()
    assert r1a != r2a           # fresh ephemerals -> different roots
    # SAS may rarely collide (7 digits) but roots must not


def test_release_mac_key_models_deniability():
    k = b"k" * 32
    assert identity.release_mac_key(k) == k   # published key == the real key
