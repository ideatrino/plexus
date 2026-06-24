"""
PLEXUS — Layer 4: the field permutation and sponge.

Every symmetric operation in PLEXUS (hashing, key derivation, message
authentication, and the pad/keystream PRG) is built from a *single* algebraic
sponge permutation, in the Poseidon / Rescue family:

    one round = [add round constants] -> [x -> x^alpha S-box] -> [MDS mixing]

The permutation operates on a state of ``T`` field elements over the
Goldilocks prime ``p = 2**64 - 2**32 + 1``.  ``x -> x^7`` is a bijection on
this field (gcd(7, p-1) == 1), the MDS matrix is a Cauchy matrix (provably
maximum-distance-separable, i.e. optimal diffusion), and the round constants
come from SHAKE256 over a fixed domain string ("nothing up my sleeve").

SECURITY NOTE
-------------
This is a faithful *reference* instantiation of the PLEXUS design, intended to
be read and reasoned about.  The round counts and parameters here have NOT been
through dedicated algebraic cryptanalysis.  For production you should either use
an audited Poseidon2 instantiation or swap this module for a SHA-3 / SHAKE256
backend (also a sponge) by reimplementing the four public functions below.
The rest of the library only depends on: hash, kdf, mac, prg, and stream.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import hashlib

# --- Field -----------------------------------------------------------------

P = (1 << 64) - (1 << 32) + 1  # Goldilocks prime
ALPHA = 7                      # S-box exponent; gcd(7, P-1) == 1 -> bijection

# --- Sponge geometry -------------------------------------------------------

T = 12          # state width (field elements)
RATE = 8        # absorbed/squeezed elements per permutation
CAP = T - RATE  # capacity = 4 elements = 256-bit capacity (~128-bit security)
BYTES_PER_ELEM = 7              # pack 7 bytes (<2^56 < P) -> no modular bias
RATE_BYTES = RATE * BYTES_PER_ELEM  # 56 bytes of rate per permutation

R_FULL = 8      # full rounds (split half/half around the partial rounds)
R_PART = 22     # partial rounds (S-box on lane 0 only)


def _derive_round_constants() -> list[list[int]]:
    """Nothing-up-my-sleeve round constants from SHAKE256."""
    n_rounds = R_FULL + R_PART
    need = n_rounds * T
    xof = hashlib.shake_256(b"PLEXUS-poseidon-v1/round-constants").digest(need * 8)
    consts, k = [], 0
    for _ in range(n_rounds):
        row = []
        for _ in range(T):
            v = int.from_bytes(xof[k:k + 8], "little") % P
            row.append(v)
            k += 8
        consts.append(row)
    return consts


def _derive_mds() -> list[list[int]]:
    """A T x T Cauchy matrix M[i][j] = 1/(x_i - y_j) -- always MDS."""
    xs = list(range(T))
    ys = list(range(100, 100 + T))
    mat = []
    for i in range(T):
        row = []
        for j in range(T):
            d = (xs[i] - ys[j]) % P
            row.append(pow(d, P - 2, P))  # modular inverse (Fermat)
        mat.append(row)
    return mat


_RC = _derive_round_constants()
_MDS = _derive_mds()


def _mds_mul(state: list[int]) -> list[int]:
    out = []
    for i in range(T):
        acc = 0
        row = _MDS[i]
        for j in range(T):
            acc += row[j] * state[j]
        out.append(acc % P)
    return out


def permutation(state: list[int]) -> list[int]:
    """The PLEXUS field permutation pi: F_p^T -> F_p^T (a bijection)."""
    s = [x % P for x in state]
    half = R_FULL // 2
    rc_idx = 0

    # first half of full rounds
    for _ in range(half):
        rc = _RC[rc_idx]; rc_idx += 1
        s = [(s[i] + rc[i]) % P for i in range(T)]
        s = [pow(s[i], ALPHA, P) for i in range(T)]
        s = _mds_mul(s)

    # partial rounds (S-box on lane 0 only)
    for _ in range(R_PART):
        rc = _RC[rc_idx]; rc_idx += 1
        s = [(s[i] + rc[i]) % P for i in range(T)]
        s[0] = pow(s[0], ALPHA, P)
        s = _mds_mul(s)

    # second half of full rounds
    for _ in range(half):
        rc = _RC[rc_idx]; rc_idx += 1
        s = [(s[i] + rc[i]) % P for i in range(T)]
        s = [pow(s[i], ALPHA, P) for i in range(T)]
        s = _mds_mul(s)

    return s


# --- byte <-> element packing ----------------------------------------------

def _bytes_to_elems(data: bytes) -> list[int]:
    assert len(data) % BYTES_PER_ELEM == 0
    return [int.from_bytes(data[i:i + BYTES_PER_ELEM], "little")
            for i in range(0, len(data), BYTES_PER_ELEM)]


def _elems_to_bytes(elems: list[int]) -> bytes:
    mask = (1 << (8 * BYTES_PER_ELEM)) - 1
    return b"".join((e & mask).to_bytes(BYTES_PER_ELEM, "little") for e in elems)


def _pad(data: bytes) -> bytes:
    # pad10*: append 0x01 then 0x00 to a multiple of RATE_BYTES
    data = data + b"\x01"
    while len(data) % RATE_BYTES != 0:
        data += b"\x00"
    return data


# --- Duplex sponge ----------------------------------------------------------

class Sponge:
    def __init__(self) -> None:
        self.state = [0] * T

    def absorb(self, data: bytes) -> "Sponge":
        data = _pad(data)
        for off in range(0, len(data), RATE_BYTES):
            block = _bytes_to_elems(data[off:off + RATE_BYTES])
            for i in range(RATE):
                self.state[i] = (self.state[i] + block[i]) % P
            self.state = permutation(self.state)
        return self

    def squeeze(self, nbytes: int) -> bytes:
        out = b""
        while len(out) < nbytes:
            out += _elems_to_bytes(self.state[:RATE])
            if len(out) < nbytes:
                self.state = permutation(self.state)
        return out[:nbytes]


# --- Public primitives (the ONLY surface the rest of PLEXUS depends on) -----

def hash(data: bytes, nbytes: int = 32) -> bytes:
    return Sponge().absorb(b"H" + data).squeeze(nbytes)


def kdf(key: bytes, info: bytes, nbytes: int = 32) -> bytes:
    return Sponge().absorb(b"K" + len(key).to_bytes(2, "little") + key + info).squeeze(nbytes)


def mac(key: bytes, data: bytes, nbytes: int = 32) -> bytes:
    return Sponge().absorb(b"M" + len(key).to_bytes(2, "little") + key + data).squeeze(nbytes)


def prg(seed: bytes, nbytes: int) -> bytes:
    return Sponge().absorb(b"P" + seed).squeeze(nbytes)


def stream(seed: bytes, nbytes: int) -> bytes:
    """Alias used by the keystream / pad layers."""
    return prg(seed, nbytes)


def ct_eq(a: bytes, b: bytes) -> bool:
    """Constant-time-ish equality for tags (reference; use hmac.compare_digest)."""
    import hmac
    return hmac.compare_digest(a, b)
