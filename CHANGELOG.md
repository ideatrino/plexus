# Changelog

All notable changes to PLEXUS are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-24

Initial public reference release.

### Added
- **Protocol specification** (`docs/SPEC.md`): six-layer braided design, threat
  model, parameters, and novelty-vs-prior-art discussion.
- **Layer 1 — `lattice`**: Ring-LWE (LPR) KEM with a Fujisaki–Okamoto transform
  and implicit rejection (Kyber-style), numpy negacyclic polynomial arithmetic.
- **Layer 2 — `ratchet`**: the braid — cross-conditioned symmetric + KEM ratchets
  bound to a running transcript hash (forward secrecy + post-compromise security).
- **Layer 3 — `pool`**: append-only entropy pool spanning computational-OTP to
  true-OTP, with non-reused pad and an optional information-theoretic budget.
- **Layer 4 — `field`**: algebraic sponge over the Goldilocks prime field
  providing hash / KDF / MAC / PRG / stream-cipher primitives.
- **Layer 5 — `cells`**: fixed-size cells, chaff, and an in-memory rendezvous relay.
- **Layer 6 — `identity`**: KEM handshake, Short Authentication String, and a
  retroactive-deniability key-release model.
- **`session`**: high-level duplex API (`Session.establish`, `send`/`receive`,
  `encrypt`/`decrypt`) tying all layers together over a relay.
- **Tests**: 38 tests across all layers, runnable via `pytest` or the
  dependency-free `run_tests.py`.
- **Example**: `examples/demo_conversation.py`, a full annotated Alice↔Bob demo.

### Security
- This release is an **unaudited reference implementation**. It is not
  constant-time and must not be used to protect real secrets. See SECURITY.md.

[0.1.0]: https://github.com/Ideatrino/plexus/releases/tag/v0.1.0
