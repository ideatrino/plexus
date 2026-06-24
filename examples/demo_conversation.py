#!/usr/bin/env python3
"""
PLEXUS demo — a full Alice <-> Bob conversation over an untrusted relay.

Run from the repo root:

    PYTHONPATH=src python examples/demo_conversation.py

It performs the handshake, prints the Short Authentication String both parties
would compare out-of-band, then exchanges messages in both directions (with
cover chaff) through an in-memory relay, showing self-healing turn-flips and a
tamper rejection at the end.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from plexus.cells import Relay                      # noqa: E402
from plexus.session import AuthenticationError, Session  # noqa: E402


def main() -> None:
    print("=" * 60)
    print("PLEXUS reference demo")
    print("=" * 60)

    # Optional: hand both directions a small genuine-shared-randomness budget so
    # the first bytes of each message are information-theoretically secure.
    te_a2b = os.urandom(32)
    te_b2a = os.urandom(32)

    alice, bob, sas = Session.establish(
        true_entropy_a2b=te_a2b, true_entropy_b2a=te_b2a
    )
    print(f"\nHandshake complete.  Compare this SAS out-of-band: {sas}")
    print("(Alice and Bob read it aloud; if it matches, no MITM.)\n")

    relay = Relay()

    script = [
        ("A", b"Hey Bob -- PLEXUS channel is live."),
        ("A", b"Sending two in a row to exercise the symmetric chain."),
        ("B", b"Got both. Replying now flips the ratchet and self-heals."),
        ("A", b"Nice -- every turn rotates our rendezvous address too."),
        ("B", b"And each cell is padded + chaffed, so the relay learns nothing."),
    ]

    for who, msg in script:
        if who == "A":
            addr = alice.send(msg, relay, n_chaff=2)
            got = bob.receive(relay)
            tag = "Alice -> Bob"
        else:
            addr = bob.send(msg, relay, n_chaff=2)
            got = alice.receive(relay)
            tag = "Bob -> Alice"
        ok = "OK" if got == msg else "MISMATCH"
        print(f"[{tag}] @{addr.hex()[:12]}…  [{ok}]  {got.decode()}")

    print(f"\nRatchet roots synchronized: {alice.ratchet.rk == bob.ratchet.rk}")
    print(f"True-OTP budget left  A->B: {alice.pool_send.true_entropy_remaining} B"
          f"  |  B->A: {bob.pool_send.true_entropy_remaining} B")

    # Tamper demonstration (operate on a direct wire frame).
    print("\nTamper test:")
    wire = bytearray(alice.encrypt(b"this should never verify if altered"))
    wire[-1] ^= 0x01
    try:
        bob.decrypt(bytes(wire))
        print("  FAILURE: tampered message was accepted!")
    except AuthenticationError:
        print("  Tampered message rejected (AuthenticationError) as expected.")

    print("\nDemo complete.")


if __name__ == "__main__":
    main()
