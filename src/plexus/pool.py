"""
PLEXUS — Layer 3: the entropy-pool pad.

A per-direction, append-only pool absorbs the pool-seed emitted by every
symmetric ratchet step.  Pad bytes are drawn from a never-rewound pointer, so
no pad byte is ever reused.

Two modes, one mechanism:

  * COMPUTATIONAL-OTP (default): pad bytes come from the sponge PRG.  Secrecy
    reduces to the sponge, not to Shannon -- but you inherit perfect forward
    secrecy of content (consumed pad is wiped) at zero key-distribution cost
    (both ends generate the pad locally from synchronized state).

  * TRUE-OTP (optional): seed the pool with genuine shared randomness
    (`true_entropy`, e.g. a physically exchanged drive or a QKD feed).  Up to
    that budget, those pad bytes are information-theoretically secure regardless
    of the adversary's computing power, quantum or not; past the budget it
    falls back to the computational stream automatically.

Sender and receiver keep mirror pools per direction, consume in lockstep, and
therefore produce identical pads.

Author: Ideatrino <ideatrino@proton.me>
Copyright (c) 2026 Ideatrino <ideatrino@proton.me>. All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

from . import field


class EntropyPool:
    def __init__(self, label: bytes = b"", true_entropy: bytes = b"") -> None:
        self.key = field.hash(b"PLEXUS-pool-init/" + label)
        self.counter = 0                 # PRG position (never rewound)
        self.true_entropy = true_entropy # optional genuine shared randomness
        self.te_ptr = 0                  # consumed-true-entropy pointer

    def absorb(self, seed: bytes) -> None:
        self.key = field.kdf(self.key + seed, b"pool-absorb", 32)

    def pad(self, n: int) -> bytes:
        out = bytearray()
        # 1) consume genuine shared randomness first (information-theoretic)
        if self.te_ptr < len(self.true_entropy):
            take = min(n, len(self.true_entropy) - self.te_ptr)
            out += self.true_entropy[self.te_ptr:self.te_ptr + take]
            self.te_ptr += take
        # 2) top up from the computational stream (never reusing positions)
        need = n - len(out)
        if need > 0:
            block = field.prg(self.key + b"pad" + self.counter.to_bytes(8, "big"), need)
            self.counter += need
            out += block
        return bytes(out)

    @property
    def true_entropy_remaining(self) -> int:
        return max(0, len(self.true_entropy) - self.te_ptr)
