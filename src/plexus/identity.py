"""
PLEXUS — Layer 6: trust without a certificate authority.

  * HANDSHAKE: a two-way KEM exchange that gives both parties an identical root
    key.  No long-term signing keys are used for message authentication, which
    preserves deniability (see below).
  * SHORT AUTHENTICATION STRING (SAS): a few human-comparable digits/words
    derived from the full handshake transcript.  Comparing it once over any
    authentic out-of-band channel (read it aloud, scan a QR in person) rules out
    a man-in-the-middle -- no PKI required.
  * DENIABILITY: messages are authenticated with a symmetric MAC under an
    ephemeral key both parties hold, never a signature, so neither can prove to a
    third party that the other authored anything.  `release_mac_key` models the
    optional publication of expired keys for strong, retroactive deniability.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import field
from .lattice import Kem, KemKeypair


def gen_identity() -> KemKeypair:
    return Kem.keygen()


@dataclass
class InitiatorHello:
    id_pub: bytes
    ct1: bytes          # encapsulation to the responder's identity key


@dataclass
class ResponderAccept:
    id_pub: bytes
    prekey_pub: bytes   # seeds the responder side of the braided ratchet
    ct2: bytes          # encapsulation to the initiator's identity key


def initiator_begin(my_id: KemKeypair, peer_id_pub: bytes) -> tuple[bytes, InitiatorHello]:
    ct1, ss1 = Kem.encap(peer_id_pub)
    return ss1, InitiatorHello(id_pub=my_id.public, ct1=ct1)


def responder_accept(
    my_id: KemKeypair, prekey: KemKeypair, hello: InitiatorHello
) -> tuple[bytes, str, ResponderAccept]:
    ss1 = Kem.decap(my_id.secret, hello.ct1)
    ct2, ss2 = Kem.encap(hello.id_pub)
    accept = ResponderAccept(id_pub=my_id.public, prekey_pub=prekey.public, ct2=ct2)
    root = _root(ss1, ss2, hello, accept)
    sas = sas_string(hello, accept)
    return root, sas, accept


def initiator_finish(
    my_id: KemKeypair, ss1: bytes, hello: InitiatorHello, accept: ResponderAccept
) -> tuple[bytes, str]:
    ss2 = Kem.decap(my_id.secret, accept.ct2)
    root = _root(ss1, ss2, hello, accept)
    sas = sas_string(hello, accept)
    return root, sas


def _transcript(hello: InitiatorHello, accept: ResponderAccept) -> bytes:
    return (
        b"PLEXUS-handshake/v1"
        + hello.id_pub + hello.ct1
        + accept.id_pub + accept.prekey_pub + accept.ct2
    )


def _root(ss1: bytes, ss2: bytes, hello: InitiatorHello, accept: ResponderAccept) -> bytes:
    return field.kdf(ss1 + ss2 + _transcript(hello, accept), b"handshake-root", 32)


def sas_string(hello: InitiatorHello, accept: ResponderAccept) -> str:
    """Seven decimal digits, grouped, for an out-of-band human compare."""
    h = field.hash(b"SAS" + _transcript(hello, accept), 8)
    n = int.from_bytes(h, "big") % 10_000_000
    s = f"{n:07d}"
    return f"{s[:3]} {s[3:5]} {s[5:]}"


def release_mac_key(mac_key: bytes) -> bytes:
    """Model retroactive deniability: an expired MAC key is published, making any
    past transcript it authenticated universally forgeable."""
    return mac_key
