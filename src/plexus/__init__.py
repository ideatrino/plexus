"""
PLEXUS — a post-quantum, metadata-resistant secure-messaging protocol.

PLEXUS braids six layers into one duplex channel:

    1. lattice  — Ring-LWE KEM (post-quantum key establishment)
    2. ratchet  — the BRAID: two cross-conditioned ratchets bound to a
                  transcript hash (forward secrecy + post-compromise security)
    3. pool     — an entropy pool spanning computational-OTP to true-OTP
    4. field    — an algebraic sponge over the Goldilocks field
                  (hash / KDF / MAC / PRG / stream cipher)
    5. cells    — fixed-size cells + chaff (length/timing/volume hiding)
    6. identity — KEM handshake with a Short Authentication String and
                  retroactive deniability

The high-level entry point is `Session` (see `plexus.session`):

    >>> from plexus import Session, Relay
    >>> alice, bob, sas = Session.establish()
    >>> relay = Relay()
    >>> _ = alice.send(b"hello", relay)
    >>> bob.receive(relay)
    b'hello'

WARNING — reference implementation.  PLEXUS composes vetted primitives in a
novel way, but the composition itself is UNAUDITED, the code is NOT
constant-time, and it must NOT be used to protect real secrets against real
adversaries until it has been independently reviewed.  See SECURITY.md.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from . import cells, field, identity, lattice, pool, ratchet, session
from .cells import Relay
from .lattice import Kem
from .pool import EntropyPool
from .ratchet import BraidRatchet
from .session import AuthenticationError, Session

__version__ = "0.1.0"
__author__ = "Ideatrino"
__email__ = "ideatrino@proton.me"
__license__ = "Proprietary"

__all__ = [
    "Session",
    "Relay",
    "Kem",
    "BraidRatchet",
    "EntropyPool",
    "AuthenticationError",
    "cells",
    "field",
    "identity",
    "lattice",
    "pool",
    "ratchet",
    "session",
    "__version__",
]
