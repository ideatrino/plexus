# PLEXUS

**A post-quantum, metadata-resistant secure-messaging protocol — reference implementation.**

[![CI](https://github.com/Ideatrino/plexus/actions/workflows/ci.yml/badge.svg)](https://github.com/Ideatrino/plexus/actions/workflows/ci.yml)
[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

PLEXUS *braids* six independent defenses into a single duplex channel. The name
(Latin *plexus*, "braid / interweaving") is the design: instead of bolting
features together, two ratchets and an entropy pool are **cross-conditioned** so
that each one's security reinforces the others.

> ⚠️ **Read this first.** PLEXUS is an original *composition* of well-studied
> primitives (Ring-LWE, sponge functions, a double ratchet). The primitives are
> standard; **the composition is new and therefore UNAUDITED.** This repository
> is a clear, tested **reference implementation** for research and review — it is
> **not** constant-time and must **not** protect real secrets against real
> adversaries until independently audited. See [SECURITY.md](SECURITY.md).

---

## Why PLEXUS

Most messengers pick a subset of the properties below. PLEXUS is an attempt to
get all of them at once, cheaply, from one coherent construction.

| Goal | How PLEXUS gets it |
|------|--------------------|
| **Post-quantum** | All key agreement is Ring-LWE (LPR) KEM with a Fujisaki–Okamoto transform — no Diffie–Hellman anywhere. |
| **OTP-grade secrecy, no OTP logistics** | A per-direction **entropy pool** produces non-reusable pad; given a real shared-randomness budget it becomes an information-theoretic one-time pad, and falls back to a computational stream automatically. |
| **Forward secrecy** | A fast symmetric chain derives a fresh key per message; spent keys are wiped. |
| **Post-compromise security ("self-healing")** | A KEM ratchet injects fresh entropy on every conversational turn-flip; one captured state heals on the next round-trip. |
| **Metadata resistance** | Fixed-size **cells** + **chaff** hide length, volume, and timing; **rotating rendezvous addresses** unlink endpoints at an untrusted relay. |
| **Deniability** | Messages are authenticated with a symmetric MAC under an ephemeral key — never a signature — so no one can prove authorship to a third party. |
| **No certificate authority** | A **Short Authentication String** (seven digits) compared once out-of-band rules out a man-in-the-middle. No PKI. |

### The braid (the core idea)

```
turn-flip ──► [ KEM ratchet ]  folds in transcript hash ──► reseeds ──┐
                                                                       ▼
every message ─────────────────► [ symmetric chain ] ──► message key ─┴─► [ entropy pool ] ─► pad
```

The asymmetric (healing) ratchet folds the **running transcript hash** into each
heal, and its output **reseeds** the fast symmetric chain. Every key therefore
depends on the entire ordered history, so reordering or tampering breaks key
agreement by construction — the integrity guarantee falls out of the braid
instead of being an add-on.

---

## Install

```bash
git clone https://github.com/Ideatrino/plexus.git
cd plexus
pip install -e .          # only dependency: numpy
```

Requires Python 3.10+.

## Quick start

```python
from plexus import Session, Relay

# In-process handshake; in practice each party runs one side.
alice, bob, sas = Session.establish()
print("Compare out-of-band:", sas)      # e.g. "667 23 81"

relay = Relay()                          # untrusted store-and-forward

alice.send(b"hello bob", relay, n_chaff=2)
print(bob.receive(relay))                # b'hello bob'

bob.send(b"hi alice", relay)             # turn-flip -> self-heals
print(alice.receive(relay))              # b'hi alice'
```

Run the full annotated demo:

```bash
PYTHONPATH=src python examples/demo_conversation.py
```

### True-OTP mode (optional)

Hand the session a budget of genuine shared randomness (a physically exchanged
drive, a QKD feed, …). Up to that budget the pad is information-theoretically
secure regardless of any adversary's computing power; past it, PLEXUS
transparently continues with the computational stream.

```python
import os
shared = os.urandom(1 << 20)             # 1 MiB pre-shared, both ends
alice, bob, sas = Session.establish(true_entropy_a2b=shared)
```

---

## The six layers

| # | Module | Role |
|---|--------|------|
| 1 | `lattice` | Ring-LWE KEM + Fujisaki–Okamoto transform (post-quantum key establishment) |
| 2 | `ratchet` | the **braid** — cross-conditioned symmetric + KEM ratchets bound to a transcript hash |
| 3 | `pool`    | append-only entropy pool: computational-OTP ↔ true-OTP |
| 4 | `field`   | algebraic sponge over the Goldilocks field → hash / KDF / MAC / PRG / stream |
| 5 | `cells`   | fixed-size cells, chaff, and an in-memory rendezvous relay |
| 6 | `identity`| KEM handshake, Short Authentication String, retroactive deniability |
| — | `session` | high-level duplex API tying all layers together |

Full design rationale, threat model, parameters, and an honest novelty-vs-prior-art
discussion are in [docs/SPEC.md](docs/SPEC.md).

---

## Tests

The suite runs **with or without pytest**:

```bash
python run_tests.py          # zero third-party deps (offline/CI friendly)
# or
pytest                       # standard
```

38 tests cover every layer: KEM round-trip correctness (the centered-binomial
sampler regression is guarded), ratchet key agreement across turn-flips, pool
lockstep + non-reuse, cell/chaff reassembly, handshake + SAS agreement, and full
end-to-end duplex with tamper rejection.

---

## Status & roadmap

This is **v0.1.0**, a feature-complete reference implementation. It is *not*
production-ready. The honest path from here:

1. **Independent cryptographic review** of the composition (the braid binding, the
   FO transform usage, the pool's pad-derivation).
2. **Constant-time, memory-hardened** primitives (the current code prioritizes
   clarity; it is not side-channel resistant).
3. Out-of-order / skipped-message key handling, formal wire spec, interop vectors.
4. A networked relay (ideally over a mixnet) replacing the in-memory `Relay`.

See [SECURITY.md](SECURITY.md) for the full limitations list and how to report
issues, and [CONTRIBUTING.md](CONTRIBUTING.md) to get involved.

## License

**Proprietary — All Rights Reserved.**
Copyright © 2026 Ideatrino <ideatrino@proton.me>. See [LICENSE](LICENSE) for the full terms.

Viewing and evaluation are permitted. Any other use — including copying, distribution,
modification, or commercial use — requires a written license agreement from Ideatrino.

**Commercial licensing & inquiries:** ideatrino@proton.me
