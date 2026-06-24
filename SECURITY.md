# Security Policy

## ⚠️ Status: unaudited reference implementation

PLEXUS composes well-studied cryptographic primitives (Ring-LWE / LPR KEM with a
Fujisaki–Okamoto transform, a sponge construction, a double ratchet) in a
**novel arrangement**. The primitives are standard; **the composition has not
been independently audited**, and the implementation deliberately favors
readability over hardening.

**Do not use PLEXUS to protect real secrets against real adversaries until it has
been independently reviewed.**

## Known limitations of this reference implementation

These are design/clarity choices in v0.x, not accidents — they are listed so no
one is surprised:

1. **Not constant-time.** Field arithmetic, comparisons, and sampling are written
   for clarity. They are **not** side-channel (timing/cache) resistant. The one
   exception is `field.ct_eq`, used for tag comparison.
2. **In-order delivery assumed.** The ratchet does not yet store keys for skipped
   or out-of-order messages. A dropped or reordered message desynchronizes the
   chain. (Roadmap item.)
3. **In-memory relay.** `cells.Relay` is a local store-and-forward stub for demos
   and tests. It is not a network service and provides no availability or mixing
   guarantees on its own.
4. **No persistent storage / key management.** Sessions live in process memory;
   there is no on-disk state, key backup, or multi-device support.
5. **Parameters are reasonable but not certification-grade.** The Ring-LWE
   parameters target ~128-bit post-quantum security by analogy to vetted schemes;
   they have not been independently re-derived or certified for this composition.
6. **Novel composition risk.** Even when every primitive is sound, *combining*
   them can introduce weaknesses. The braid binding, the FO usage, and the pool's
   pad derivation are exactly the parts that most need expert review.
7. **No formal proof.** There is no machine-checked or hand-written security proof
   of the overall protocol yet.

## What *is* tested

The included suite (`python run_tests.py` or `pytest`) verifies functional
correctness: KEM round-trip soundness, ratchet key agreement across turn-flips,
entropy-pool lockstep and non-reuse, cell/chaff reassembly, handshake and SAS
agreement, and end-to-end duplex with tamper rejection. Functional tests are not
a security audit.

## Reporting a vulnerability

If you believe you have found a security issue, please report it **privately**
first rather than opening a public issue:

- Email: **ideatrino@proton.me**
- Please include a description, affected version/commit, and a reproduction if
  possible.

You can expect an acknowledgement within a reasonable time. Because this is an
unaudited research project, coordinated disclosure is appreciated but there is no
bug-bounty program at this stage.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ (current; reference only) |
