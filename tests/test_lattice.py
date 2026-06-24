"""Tests for Layer 1: the Ring-LWE KEM (plexus.lattice)."""

from __future__ import annotations

from plexus.lattice import Kem


def test_keygen_sizes():
    kp = Kem.keygen()
    assert len(kp.public) == 544
    # secret packs the CPA secret + pk + hashes for the FO transform
    assert len(kp.secret) > 544


def test_roundtrip_correctness_many():
    # The centered-binomial sampler bug (uint8 underflow) once caused 100% decap
    # failure; this guards against any regression.  Zero failures expected.
    failures = 0
    for _ in range(200):
        kp = Kem.keygen()
        ct, ss_enc = Kem.encap(kp.public)
        ss_dec = Kem.decap(kp.secret, ct)
        if ss_enc != ss_dec:
            failures += 1
    assert failures == 0, f"{failures}/200 KEM round-trips failed"


def test_shared_secret_size():
    kp = Kem.keygen()
    ct, ss = Kem.encap(kp.public)
    assert len(ss) == 32
    assert len(ct) == 1024


def test_implicit_reject_on_tamper():
    kp = Kem.keygen()
    ct, ss = Kem.encap(kp.public)
    bad = bytearray(ct)
    bad[0] ^= 0xFF
    ss_bad = Kem.decap(kp.secret, bytes(bad))
    # FO transform: a tampered ciphertext yields a different (pseudo-random) ss,
    # never the real one, and never an error.
    assert ss_bad != ss


def test_independent_keys_differ():
    a = Kem.keygen()
    b = Kem.keygen()
    assert a.public != b.public
    # encapsulating to different keys gives different secrets
    _, ssa = Kem.encap(a.public)
    _, ssb = Kem.encap(b.public)
    assert ssa != ssb
