"""
PLEXUS — Layer 1: the post-quantum lattice KEM.

A Ring-LWE (LPR) public-key encryption scheme over R_q = Z_q[x]/(x^n + 1),
wrapped in a Fujisaki-Okamoto transform to obtain an IND-CCA2 key
encapsulation mechanism (KEM) with implicit rejection -- the same template
that underlies ML-KEM / Kyber.

Hardness rests on Module/Ring-LWE: distinguishing b = a*s + e from uniform,
believed hard even for quantum computers (Shor's algorithm does not threaten
the closest-vector geometry of a random lattice).

Parameters (n=256, q=3329, eta=2) give negligible decryption-failure
probability without ciphertext compression, which keeps this reference
implementation simple and exactly correct.

SECURITY NOTE
-------------
Reference implementation: correct and CCA-structured, but NOT constant-time and
NOT side-channel hardened.  For production, link a vetted ML-KEM implementation
behind the same Kem interface.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np

from . import field

N = 256
Q = 3329
ETA = 2
HALF_Q = Q // 2          # 1664, used to encode a message bit
POLY_BYTES = N * 2       # 2 bytes/coeff, uncompressed
SEED_BYTES = 32


# --- polynomial arithmetic in R_q = Z_q[x]/(x^n + 1) -----------------------

def _poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    c = np.convolve(a.astype(np.int64), b.astype(np.int64))   # length 2N-1
    res = c[:N].copy()
    res[:N - 1] -= c[N:2 * N - 1]      # x^n = -1  (negacyclic fold)
    return np.mod(res, Q).astype(np.int64)


def _poly_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return np.mod(a + b, Q).astype(np.int64)


def _poly_sub(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return np.mod(a - b, Q).astype(np.int64)


# --- samplers ---------------------------------------------------------------

def _cbd(seed: bytes, nonce: int) -> np.ndarray:
    """Centered binomial distribution in [-ETA, ETA], from a PRG stream."""
    need = N * ETA * 2 // 8  # bits -> bytes; ETA=2 -> N/2 bytes
    buf = field.prg(seed + b"cbd" + nonce.to_bytes(2, "little"), need)
    bits = np.unpackbits(np.frombuffer(buf, dtype=np.uint8))
    bits = bits[: N * 2 * ETA].reshape(N, 2 * ETA).astype(np.int64)
    a = bits[:, :ETA].sum(axis=1)
    b = bits[:, ETA:].sum(axis=1)
    return np.mod(a - b, Q).astype(np.int64)


def _uniform(seed: bytes) -> np.ndarray:
    """Uniform poly in R_q from a seed (rejection sampling on 12-bit chunks)."""
    out = np.empty(N, dtype=np.int64)
    filled = 0
    ctr = 0
    while filled < N:
        buf = field.prg(seed + b"unif" + ctr.to_bytes(2, "little"), 512)
        vals = np.frombuffer(buf, dtype=np.uint16) & 0x0FFF  # 12 bits -> 0..4095
        vals = vals[vals < Q]
        take = min(len(vals), N - filled)
        out[filled:filled + take] = vals[:take]
        filled += take
        ctr += 1
    return out


# --- (de)serialization ------------------------------------------------------

def _pack(p: np.ndarray) -> bytes:
    return p.astype("<u2").tobytes()


def _unpack(b: bytes) -> np.ndarray:
    return np.frombuffer(b, dtype="<u2").astype(np.int64)


def _encode_msg(m: bytes) -> np.ndarray:
    bits = np.unpackbits(np.frombuffer(m, dtype=np.uint8))  # 256 bits
    return (bits.astype(np.int64) * HALF_Q)


def _decode_msg(p: np.ndarray) -> bytes:
    # bit = 1 iff coeff lies in the middle half [q/4, 3q/4)
    bit = ((p >= Q // 4) & (p < 3 * Q // 4)).astype(np.uint8)
    return np.packbits(bit).tobytes()


# --- CPA-secure PKE ---------------------------------------------------------

def _cpa_keygen() -> tuple[bytes, bytes]:
    seed_a = os.urandom(SEED_BYTES)
    noise = os.urandom(SEED_BYTES)
    a = _uniform(seed_a)
    s = _cbd(noise, 0)
    e = _cbd(noise, 1)
    b = _poly_add(_poly_mul(a, s), e)
    pk = seed_a + _pack(b)
    sk = _pack(s)
    return pk, sk


def _cpa_enc(pk: bytes, m: bytes, coins: bytes) -> bytes:
    seed_a, b_bytes = pk[:SEED_BYTES], pk[SEED_BYTES:]
    a = _uniform(seed_a)
    b = _unpack(b_bytes)
    r = _cbd(coins, 0)
    e1 = _cbd(coins, 1)
    e2 = _cbd(coins, 2)
    u = _poly_add(_poly_mul(a, r), e1)
    v = _poly_add(_poly_add(_poly_mul(b, r), e2), _encode_msg(m))
    return _pack(u) + _pack(v)


def _cpa_dec(sk: bytes, c: bytes) -> bytes:
    s = _unpack(sk)
    u = _unpack(c[:POLY_BYTES])
    v = _unpack(c[POLY_BYTES:])
    mp = _poly_sub(v, _poly_mul(u, s))
    return _decode_msg(mp)


# --- FO transform -> IND-CCA2 KEM ------------------------------------------

def _G(x: bytes) -> tuple[bytes, bytes]:
    out = field.kdf(x, b"FO-G", 64)
    return out[:32], out[32:]          # (Kbar, coins)


def _H(x: bytes) -> bytes:
    return field.hash(x, 32)


def _ss(x: bytes) -> bytes:
    return field.kdf(x, b"FO-ss", 32)


@dataclass
class KemKeypair:
    public: bytes
    secret: bytes


class Kem:
    """The interface the rest of PLEXUS depends on."""

    @staticmethod
    def keygen() -> KemKeypair:
        pk, sk_cpa = _cpa_keygen()
        z = os.urandom(SEED_BYTES)
        sk = sk_cpa + pk + _H(pk) + z
        return KemKeypair(public=pk, secret=sk)

    @staticmethod
    def encap(public: bytes) -> tuple[bytes, bytes]:
        m = os.urandom(SEED_BYTES)
        Kbar, coins = _G(m + _H(public))
        c = _cpa_enc(public, m, coins)
        return c, _ss(Kbar + _H(c))

    @staticmethod
    def decap(secret: bytes, c: bytes) -> bytes:
        sk_cpa = secret[:POLY_BYTES]
        rest = secret[POLY_BYTES:]
        pk = rest[: SEED_BYTES + POLY_BYTES]
        hpk = rest[SEED_BYTES + POLY_BYTES: SEED_BYTES + POLY_BYTES + 32]
        z = rest[SEED_BYTES + POLY_BYTES + 32:]
        m2 = _cpa_dec(sk_cpa, c)
        Kbar2, coins2 = _G(m2 + hpk)
        c2 = _cpa_enc(pk, m2, coins2)
        if field.ct_eq(c2, c):
            return _ss(Kbar2 + _H(c))
        return _ss(z + _H(c))          # implicit reject
