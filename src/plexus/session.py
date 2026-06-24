"""
PLEXUS — the high-level Session API.

A `Session` braids all six layers into a single duplex channel:

    plaintext
      -> Layer 2 braided ratchet      (message key + pool seed; forward secrecy
                                        + post-compromise security)
      -> Layer 3 entropy-pool pad      (OTP-flavoured / true-OTP)
      -> per-message keystream + MAC   (confidentiality + deniable authenticity)
      -> Layer 5 fixed cells + chaff   (length/timing/volume hiding)
      -> rendezvous mailbox on a relay (unlinkable routing)

`Session.establish()` runs the Layer 6 handshake in-process and returns a wired
pair plus the Short Authentication String to compare out-of-band.

Reference limitations (documented, not hidden): in-order delivery is assumed
(no skipped-message key storage); the transport relay is in-memory; primitives
are not constant-time.  See SECURITY.md.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from . import cells, field, identity
from .pool import EntropyPool
from .ratchet import BraidRatchet


class AuthenticationError(Exception):
    """Raised when a message authentication tag fails to verify."""


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


class Session:
    def __init__(
        self,
        ratchet: BraidRatchet,
        addr_seed: bytes,
        send_dir: bytes,
        recv_dir: bytes,
        true_entropy_send: bytes = b"",
        true_entropy_recv: bytes = b"",
    ) -> None:
        self.ratchet = ratchet
        self.addr_seed = addr_seed
        self.send_dir = send_dir
        self.recv_dir = recv_dir
        self.pool_send = EntropyPool(label=send_dir, true_entropy=true_entropy_send)
        self.pool_recv = EntropyPool(label=recv_dir, true_entropy=true_entropy_recv)
        self.send_index = 0
        self.recv_index = 0

    # -- pairing (handshake) -------------------------------------------------

    @classmethod
    def establish(
        cls, true_entropy_a2b: bytes = b"", true_entropy_b2a: bytes = b""
    ) -> tuple["Session", "Session", str]:
        a_id = identity.gen_identity()
        b_id = identity.gen_identity()
        b_prekey = identity.gen_identity()

        ss1, hello = identity.initiator_begin(a_id, b_id.public)
        root_b, sas_b, accept = identity.responder_accept(b_id, b_prekey, hello)
        root_a, sas_a = identity.initiator_finish(a_id, ss1, hello, accept)

        assert root_a == root_b, "handshake root mismatch"
        assert sas_a == sas_b, "SAS mismatch"

        alice = cls(
            BraidRatchet.initiator(root_a, accept.prekey_pub),
            addr_seed=root_a, send_dir=b"A2B", recv_dir=b"B2A",
            true_entropy_send=true_entropy_a2b, true_entropy_recv=true_entropy_b2a,
        )
        bob = cls(
            BraidRatchet.responder(root_b, b_prekey),
            addr_seed=root_b, send_dir=b"B2A", recv_dir=b"A2B",
            true_entropy_send=true_entropy_b2a, true_entropy_recv=true_entropy_a2b,
        )
        return alice, bob, sas_a

    # -- core crypto ---------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        hbytes, mk, seed = self.ratchet.send_step()
        self.pool_send.absorb(seed)
        mk_enc = field.kdf(mk, b"msg-enc", 32)
        mk_mac = field.kdf(mk, b"msg-mac", 32)
        n = len(plaintext)
        keystream = field.stream(mk_enc, n)
        pad = self.pool_send.pad(n)
        body = _xor(_xor(plaintext, keystream), pad)
        tag = field.mac(mk_mac, hbytes + body)
        return len(hbytes).to_bytes(2, "big") + hbytes + tag + body

    def decrypt(self, wire: bytes) -> bytes:
        hlen = int.from_bytes(wire[:2], "big")
        hbytes = wire[2:2 + hlen]
        tag = wire[2 + hlen:2 + hlen + 32]
        body = wire[2 + hlen + 32:]
        mk, seed = self.ratchet.recv_step(hbytes)
        self.pool_recv.absorb(seed)
        mk_enc = field.kdf(mk, b"msg-enc", 32)
        mk_mac = field.kdf(mk, b"msg-mac", 32)
        if not field.ct_eq(tag, field.mac(mk_mac, hbytes + body)):
            raise AuthenticationError("MAC verification failed")
        n = len(body)
        keystream = field.stream(mk_enc, n)
        pad = self.pool_recv.pad(n)
        return _xor(_xor(body, keystream), pad)

    # -- transport (cells + chaff + rendezvous) ------------------------------

    def _addr(self, direction: bytes, index: int) -> bytes:
        return field.hash(self.addr_seed + b"addr" + direction + index.to_bytes(8, "big"), 16)

    def _cell_key(self, addr: bytes) -> bytes:
        return field.hash(self.addr_seed + b"cellkey" + addr, 32)

    def send(self, plaintext: bytes, relay: "cells.Relay", n_chaff: int = 0) -> bytes:
        wire = self.encrypt(plaintext)
        addr = self._addr(self.send_dir, self.send_index)
        ck = self._cell_key(addr)
        outgoing = cells.to_cells(wire) + [cells.chaff_cell() for _ in range(n_chaff)]
        for cell in outgoing:
            relay.put(addr, _xor(cell, field.stream(ck, cells.CELL_SIZE)))
        self.send_index += 1
        return addr

    def receive(self, relay: "cells.Relay") -> bytes:
        addr = self._addr(self.recv_dir, self.recv_index)
        ck = self._cell_key(addr)
        payload = b""
        for enc in relay.get(addr):
            cell = _xor(enc, field.stream(ck, cells.CELL_SIZE))
            data = cells.cell_payload(cell)
            if data is not None:               # drop chaff
                payload += data
        self.recv_index += 1
        return self.decrypt(payload)
