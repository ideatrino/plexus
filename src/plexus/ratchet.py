"""
PLEXUS — Layer 2: the braid (the double ratchet).

Two ratchets woven into one:

  * SYMMETRIC chain (fast)   -> a fresh message key for every message
                               => forward secrecy
  * ASYMMETRIC chain (KEM)   -> a fresh shared secret on every conversational
                               turn-flip (the post-quantum analogue of Signal's
                               Diffie-Hellman ratchet)
                               => post-compromise security ("self-healing")

The braid: the asymmetric step folds in the running TRANSCRIPT hash (so a heal
is bound to everything said so far), and its output reseeds the symmetric chain
(so the fast chain is conditioned on the healing chain).  Every key therefore
depends on the entire ordered history -> tamper / reorder resistance is baked in.

Each symmetric step emits (chain_key', message_key, pool_seed); the pool_seed
feeds Layer 3 (the entropy pool).  Delivery is assumed in-order in this
reference (skipped-message key storage is a documented TODO).

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import field
from .lattice import Kem, KemKeypair


def _split(blob: bytes) -> tuple[bytes, bytes, bytes]:
    return blob[:32], blob[32:64], blob[64:96]


@dataclass
class Header:
    ratchet: bool
    counter: int
    pub: bytes = b""
    ct: bytes = b""

    def serialize(self) -> bytes:
        out = bytes([1 if self.ratchet else 0]) + self.counter.to_bytes(4, "big")
        if self.ratchet:
            out += len(self.pub).to_bytes(2, "big") + self.pub
            out += len(self.ct).to_bytes(2, "big") + self.ct
        return out

    @staticmethod
    def parse(buf: bytes) -> tuple["Header", int]:
        ratchet = bool(buf[0])
        counter = int.from_bytes(buf[1:5], "big")
        off = 5
        pub = ct = b""
        if ratchet:
            lp = int.from_bytes(buf[off:off + 2], "big"); off += 2
            pub = buf[off:off + lp]; off += lp
            lc = int.from_bytes(buf[off:off + 2], "big"); off += 2
            ct = buf[off:off + lc]; off += lc
        return Header(ratchet, counter, pub, ct), off


class BraidRatchet:
    def __init__(self, root: bytes) -> None:
        self.rk = root
        self.ck_send: bytes | None = None
        self.ck_recv: bytes | None = None
        self.self_kem: KemKeypair | None = None
        self.peer_pub: bytes | None = None
        self.recv_pub_is_new = False
        self.n_send = 0
        self.n_recv = 0
        self.th = field.hash(b"PLEXUS-transcript-init/v1")

    # -- construction --------------------------------------------------------

    @classmethod
    def initiator(cls, root: bytes, responder_prekey_pub: bytes) -> "BraidRatchet":
        r = cls(root)
        r.peer_pub = responder_prekey_pub        # will encap to this on first send
        return r

    @classmethod
    def responder(cls, root: bytes, prekey: KemKeypair) -> "BraidRatchet":
        r = cls(root)
        r.self_kem = prekey                       # initiator encaps to this first
        return r

    # -- internal root (asymmetric) step ------------------------------------

    def _root_step_send(self) -> Header:
        assert self.peer_pub is not None, "no peer ratchet key yet (cannot open epoch)"
        ct, ss = Kem.encap(self.peer_pub)
        out = field.kdf(self.rk + ss + self.th, b"braid-root", 64)
        self.rk, self.ck_send = out[:32], out[32:]
        self.self_kem = Kem.keygen()              # fresh key for the reverse direction
        self.n_send = 0
        self.recv_pub_is_new = False
        return Header(ratchet=True, counter=self.n_send, pub=self.self_kem.public, ct=ct)

    def _root_step_recv(self, hdr: Header) -> None:
        assert self.self_kem is not None, "no local ratchet key to decapsulate with"
        ss = Kem.decap(self.self_kem.secret, hdr.ct)
        out = field.kdf(self.rk + ss + self.th, b"braid-root", 64)
        self.rk, self.ck_recv = out[:32], out[32:]
        self.peer_pub = hdr.pub
        self.recv_pub_is_new = True

    # -- public message API --------------------------------------------------

    def send_step(self) -> tuple[bytes, bytes, bytes]:
        """Returns (header_bytes, message_key, pool_seed)."""
        if self.ck_send is None or self.recv_pub_is_new:
            hdr = self._root_step_send()
        else:
            hdr = Header(ratchet=False, counter=self.n_send)
        hbytes = hdr.serialize()
        self.th = field.hash(self.th + hbytes)
        ck2, mk, seed = _split(field.kdf(self.ck_send + self.th, b"braid-chain", 96))
        self.ck_send = ck2
        self.n_send += 1
        return hbytes, mk, seed

    def recv_step(self, hbytes: bytes) -> tuple[bytes, bytes]:
        """Returns (message_key, pool_seed)."""
        hdr, _ = Header.parse(hbytes)
        if hdr.ratchet:
            self._root_step_recv(hdr)
        self.th = field.hash(self.th + hbytes)
        ck2, mk, seed = _split(field.kdf(self.ck_recv + self.th, b"braid-chain", 96))
        self.ck_recv = ck2
        self.n_recv += 1
        return mk, seed

    # -- rendezvous address (Layer 5 hook) ----------------------------------

    def rendezvous(self, label: bytes = b"") -> bytes:
        return field.hash(self.rk + b"rendezvous" + label, 16)
