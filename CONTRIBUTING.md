# Contributing to PLEXUS

Thanks for your interest! PLEXUS is a research-grade reference implementation of a
novel secure-messaging protocol, and the most valuable contributions right now
are **review and scrutiny**, not just features.

## Most wanted

1. **Cryptographic review.** If you have crypto expertise, the highest-value
   contribution is analysis of the *composition* — the braid binding between the
   two ratchets, the Fujisaki–Okamoto usage in `lattice`, and the pad derivation
   in `pool`. Found a weakness? See [SECURITY.md](SECURITY.md) for private
   reporting.
2. **Constant-time / hardened primitives.** The current `field` and `lattice`
   code prioritizes clarity and is not side-channel resistant. Drop-in hardened
   replacements (with tests) are very welcome.
3. **Out-of-order message handling.** Skipped-message key storage in the ratchet.
4. **A real networked relay** to replace the in-memory `cells.Relay`.

## Development setup

```bash
git clone https://github.com/Ideatrino/plexus.git
cd plexus
pip install -e ".[dev]"
```

## Running tests

The suite runs with or without third-party dependencies:

```bash
python run_tests.py     # zero deps
pytest                  # if installed
```

Please ensure **all tests pass** and add tests for any new behavior. New
cryptographic code without tests will not be merged.

## Code style

- Python 3.10+, type hints on public functions.
- Keep modules single-responsibility and readable — this is a *reference*
  implementation; clarity beats cleverness.
- Each source file carries the standard header attributing authorship and the
  Apache-2.0 license.
- Run `ruff` / `black` if you have them; match the surrounding style otherwise.

## Pull requests

- Branch from `main`, keep PRs focused.
- Describe *what* and *why*; link any related issue.
- For protocol or wire-format changes, update `docs/SPEC.md` and `CHANGELOG.md`.

## Licensing of contributions

By submitting a contribution you agree it is licensed under the project's
[Apache-2.0](LICENSE) license. See [AUTHORS](AUTHORS) — add yourself.

## Code of conduct

Be respectful and constructive. Assume good faith. Security research is welcome;
attacks on the *protocol* are the point. Attacks on *people* are not.
