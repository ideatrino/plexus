# PLEXUS

### A braided, post‑quantum, metadata‑resistant communication protocol

*"Plexus" (Latin): an interweaving, a braid. The name describes the core idea — two cryptographic ratchets braided into one strand, conditioned on each other.*

> This document is the complete, self-contained specification. The accompanying
> reference implementation lives in `src/plexus/`.

---

## 0. The honest premise (read this first)

In cryptography there are two kinds of "original":

1. **Inventing a new hardness assumption** (a brand‑new "hard math problem" nobody has analyzed). This is almost always a *mistake*. New assumptions are broken constantly. Doing this would make PLEXUS *less* secure, not more.
2. **Inventing a new composition** — assembling well‑studied, individually‑vetted mathematical primitives into a new architecture that achieves properties no single existing system gives you at once.

PLEXUS is original in sense (2), which is the *only* responsible way to design something both **new** and **secure**. Every hard problem it relies on is one that the world's cryptanalysts have failed to break for years. What is genuinely new is the **way they are braided together**. Section 13 is brutally explicit about which ideas are novel and which stand on giants.

---

## 1. Design goals (the shortcomings of existing systems, made into requirements)

| # | Existing shortcoming | PLEXUS requirement |
|---|---|---|
| G1 | RSA/ECC die to a quantum computer (Shor's algorithm) | **Post‑quantum** confidentiality + key agreement |
| G2 | The one‑time pad is unbreakable but its key is as long as the message and impossible to distribute | **OTP‑grade secrecy without OTP‑grade key logistics** |
| G3 | Symmetric ciphers have a key‑distribution problem | Self‑bootstrapping keys via KEM + ratchet |
| G4 | A stolen key decrypts the *past* (no forward secrecy) | **Forward secrecy** — every message, its own key |
| G5 | A stolen key decrypts the *future* forever | **Post‑compromise security** — the channel *heals itself* |
| G6 | Encrypted content still leaks *who talks to whom, when, how much* | **Metadata resistance** |
| G7 | Digital signatures *prove* you said it (no deniability) | **Cryptographic deniability** |
| G8 | PKI / certificate authorities are central points of trust & failure | **Trust‑on‑first‑use** identity, no CA required |

The thesis: **no widely deployed system delivers G1–G8 simultaneously.** PLEXUS is built to.

---

## 2. Threat model

The adversary, **Eve**, is assumed to be maximally strong short of magic:

- **Active network attacker** — reads, drops, reorders, replays, and injects any traffic.
- **Quantum‑capable** — owns a large fault‑tolerant quantum computer.
- **Global passive observer** — sees *all* metadata everywhere (timing, volume, addresses).
- **Episodically intrusive** — can fully compromise an endpoint and steal its entire state for a *bounded* window, then loses access. (PLEXUS must recover after she leaves.)

Eve is *not* assumed to break standard hardness assumptions (Module‑LWE, a secure sponge permutation, a secure hash) or to control the human out‑of‑band channel used once for authentication.

---

## 3. Architecture — the six interwoven layers

```
                        ┌───────────────────────────────────────┐
   message in  ───────▶ │  L3  ENTROPY‑POOL PAD   (computational │
                        │      → information‑theoretic OTP mode) │
                        └───────────────────┬───────────────────┘
                                            │ keyed by
        ┌───────────────────────────────────┴───────────────────┐
        │            L2  THE BRAID  (two ratchets, woven)        │
        │   ┌────────────────────┐      ┌────────────────────┐   │
        │   │ FIELD ratchet      │◀────▶│ LATTICE ratchet    │   │
        │   │ (fast, per‑message)│ braid│ (healing, periodic)│   │
        │   │  → forward secrecy │      │ → post‑compromise  │   │
        │   └─────────┬──────────┘      └─────────┬──────────┘   │
        └─────────────┼───────────────────────────┼─────────────┘
                      │ built on                   │ built on
              ┌───────▼─────────┐         ┌────────▼──────────┐
              │ L4 FIELD PERM   │         │ L1 LATTICE CORE   │
              │ (algebraic      │         │ (Module‑LWE KEM,  │
              │  sponge)        │         │  FO‑transformed)  │
              └─────────────────┘         └───────────────────┘
                      │                            │
        ┌─────────────▼────────────────────────────▼───────────┐
        │ L5 METADATA SKIN: fixed cells · chaff · rendezvous    │
        │ L6 TRUST: deniable MACs · short‑auth‑string identity  │
        └───────────────────────────────────────────────────────┘
                                    │
                          ciphertext cells out
```

---

## 4. Layer 1 — the lattice core (post‑quantum, solves G1)

This layer deliberately mirrors the well‑analyzed **Module‑LWE** construction. We innovate *above* it, not inside it.

**Ring.** Work in $R_q = \mathbb{Z}_q[X]/(X^n+1)$ with $n$ a power of two and prime $q \equiv 1 \pmod{2n}$ (so the Number‑Theoretic Transform gives fast multiplication). Module rank $k$. Small "noise" is sampled from a centered binomial $\beta_\eta$.

**Key generation.**
- Expand public matrix $\mathbf{A}\in R_q^{k\times k}$ from a public seed $\rho$.
- Sample small secret $\mathbf{s}$ and small error $\mathbf{e}$.
- Public key $\mathbf{t} = \mathbf{A}\mathbf{s} + \mathbf{e}$.  Secret key is $\mathbf{s}$.

**Encapsulation (CPA core).** To send an $n$‑bit value $m$:
- sample small $\mathbf{r}, \mathbf{e}_1, e_2$,
- $\mathbf{u} = \mathbf{A}^{T}\mathbf{r} + \mathbf{e}_1$,
- $v = \mathbf{t}^{T}\mathbf{r} + e_2 + \lfloor q/2 \rceil\, m$.

**Decapsulation.** Compute $v - \mathbf{s}^{T}\mathbf{u} = \lfloor q/2\rceil\, m + (\text{small})$, then round each coefficient to $0$ or $\lfloor q/2\rceil$ to recover $m$.

**Why it's safe:** distinguishing $\mathbf{t}$ from random, or recovering $\mathbf{s}$, is the **Module‑LWE problem** — believed hard even for quantum computers, because Shor's algorithm attacks *periodicity/structure in abelian groups*, not the *closest‑vector geometry* of a random lattice.

**CCA hardening.** Wrap the above in the **Fujisaki–Okamoto transform** to get an IND‑CCA2 **KEM**: derive randomness from a hash of the message, re‑encrypt on decapsulation, and reject on mismatch. This is what makes the KEM safe against Eve's active tampering. PLEXUS uses *this KEM*, never the raw CPA scheme, as a black box: `(pk, sk) ← KeyGen()`, `(ct, ss) ← Encap(pk)`, `ss ← Decap(sk, ct)`.

---

## 5. Layer 4 — the field permutation (the symmetric heart, solves nothing alone but powers L2/L3)

Everything symmetric in PLEXUS — every KDF, MAC, hash, and pad byte — is one **sponge** built on a single permutation $\pi$ over state $\mathbf{x}\in\mathbb{F}_p^{\,t}$ ($t$ words). This is an *algebraic* sponge (Poseidon/Rescue family), chosen because it is analyzable with clean algebraic tools rather than hand‑tuned bit hacks.

One round of $\pi$:

1. **Nonlinear layer** — apply the power map $S(x)=x^{\alpha}$ to each word, where $\gcd(\alpha,\,p-1)=1$ so $S$ is a *bijection*. (Small $\alpha$ like 3 or 5 keeps it fast; invertibility keeps $\pi$ a true permutation.)
2. **Linear mixing** — multiply the state by an **MDS matrix** $M$. MDS guarantees branch number $t+1$ (provably optimal diffusion: any nonzero input difference touches the maximum number of outputs).
3. **Round constants** — add distinct constants $c_r$ per round to kill symmetry and slide attacks.

Iterate $\rho_f$ full rounds (optionally some cheaper partial rounds in the middle, Poseidon‑style, for speed). $\pi$ is invertible because each layer is.

From $\pi$ we get a **duplex sponge**: `Absorb(data)` XORs/adds data into the rate portion and applies $\pi$; `Squeeze(ℓ)` reads out $\ell$ words, applying $\pi$ as needed. The capacity portion is never exposed, which is what provides the security margin. **All** of: `H(·)` (hash), `KDF(·)`, `MAC_k(·)`, and the entropy‑pad stream are just this one duplex with different domain‑separation tags.

---

## 6. Layer 2 — THE BRAID (the original core; solves G3, G4, G5)

Two ratchets run at once and are **woven together** so that each repeatedly re‑seeds and is bound to the other. This is the heart of what's new.

### The FIELD ratchet — fast, per message → forward secrecy (G4)

A symmetric chain. For message $i$, with running transcript hash $H_i = \mathrm{H}(H_{i-1}\,\|\,\text{header}_i)$:

$$ (ck_{i+1},\; mk_i,\; a_i) \;=\; \mathrm{Squeeze}\big(\mathrm{Absorb}(ck_i \,\|\, H_i)\big) $$

- $mk_i$ — the one‑time **message key** (used once, then wiped). Stealing today's $ck$ cannot recompute yesterday's $mk$ because $\pi$ is one‑way in the sponge → **forward secrecy, every message.**
- $a_i$ — an **entropy contribution** fed to Layer 3 (Section 7).
- $H_i$ binds the *entire ordered conversation so far* into every key → tamper/reorder evidence is baked in.

### The LATTICE ratchet — periodic → post‑compromise security (G5)

Every epoch (every $T$ messages or on a timer), each party generates a **fresh ephemeral KEM keypair**, ships the public key, both run `Encap/Decap`, and obtain a fresh shared secret $ss_j$. The **root key** advances:

$$ (rk_{j+1},\; ck_0^{(j+1)}) \;=\; \mathrm{KDF}\big(rk_j \,\|\, ss_j \,\|\, H_{\text{epoch}}\big) $$

Because $ss_j$ comes from *freshly generated* secrets that never touched the old compromised state, **one clean epoch after Eve leaves locks her out forever** — the channel heals itself.

### The BRAID — why it's woven, not just stacked

Two bindings turn two ratchets into one strand:

- **Lattice ⟵ Field:** the new root absorbs $H_{\text{epoch}}$ — the *accumulated symmetric transcript*. The healing step is conditioned on everything the fast chain did.
- **Field ⟵ Lattice:** each epoch's $ss_j$ seeds the *next* field chain via $ck_0^{(j+1)}$. The fast chain is conditioned on the healing chain.

Consequence: compromising the state of *one* ratchet does not let Eve cleanly predict the *other* across a healing boundary, and the woven transcript hash means she cannot splice, reorder, or replay across the braid without detection. Forward secrecy (fast) and post‑compromise security (periodic) coexist **cheaply** — you pay for expensive lattice operations only once per epoch, not per message.

---

## 7. Layer 3 — the entropy‑pool pad (solves G2; spans computational ↔ information‑theoretic)

This is the layer that chases the **one‑time pad's unbreakable secrecy** while dodging its fatal key‑logistics problem.

Both parties maintain a synchronized, append‑only **entropy pool** $P$. After every field step, the contribution $a_i$ (Section 6) is absorbed:  $P \leftarrow \mathrm{Absorb}(P \,\|\, a_i)$. A never‑rewound pointer marks consumed bits.

To send a message of length $\ell$: draw $\ell$ **fresh, never‑reused** bits $\pi_\ell$ from $P$, advance the pointer, and XOR:

$$ c \;=\; \text{plaintext} \oplus \pi_\ell \quad(\text{then wrapped in the authenticated envelope of §9}). $$

Two modes, one mechanism:

- **Computational‑OTP mode (default).** Pad bits come from the sponge PRG, so secrecy reduces to the sponge — *not* Shannon‑perfect, but you inherit **perfect forward secrecy of content** (used pad bits are destroyed) and **zero key‑distribution cost** (both ends generate the pad locally from synchronized state). This is exactly the OTP property G2 wanted, minus the impossible logistics.
- **True‑OTP mode (optional).** Pre‑seed $P$ with *genuine* shared randomness — a physically exchanged drive of quantum/hardware‑RNG bytes, or a QKD feed. Up to that entropy budget, secrecy becomes **information‑theoretic** in the Shannon sense: unbreakable regardless of Eve's computing power, quantum or not.

PLEXUS therefore **degrades gracefully**: as much information‑theoretic security as your true‑entropy budget allows, falling back to strong post‑quantum computational security when the budget runs out — on the *same* channel, transparently.

---

## 8. Layer 5 — the metadata skin (solves G6)

Encrypting content is not enough; *patterns* leak. The skin removes them.

- **Fixed‑size cells.** Everything is fragmented/padded to constant‑size cells (e.g. 512 B). Message length is invisible.
- **Constant‑rate chaff.** Each party emits cells on a fixed schedule; when there's nothing to say, it sends **dummy cells** that are byte‑indistinguishable from real ones (all cells are sponge‑encrypted). Timing and volume leak nothing.
- **Rendezvous addressing.** Instead of stable "from/to" addresses, both parties *derive* rotating ephemeral mailbox IDs from shared state:
  $$ \mathrm{addr}_j = \mathrm{H}(rk_j \,\|\, \text{"addr"} \,\|\, j). $$
  They drop and fetch cells at these addresses on an untrusted relay/store. An observer sees unlinkable random addresses that rotate every epoch and **cannot tie the two parties together over time.** (Composes naturally with a mixnet for network‑layer anonymity.) This reuses the ratchet state you already have — no extra secret needed.

---

## 9. Layer 6 — deniability + identity (solves G7, G8)

**Deniability (G7).** Messages are authenticated with a **MAC** under an ephemeral key from the ratchet — *not* a digital signature:

$$ \text{tag} = \mathrm{MAC}_{mk_i}(\text{header}_i \,\|\, c). $$

Because *both* parties hold $mk_i$, **either** could have produced any transcript, so neither can prove to a third party that the *other* authored anything → **participation/authorship deniability.** Optionally, expired MAC keys are periodically *published*, making every past transcript *universally forgeable* — strong, retroactive deniability.

**Identity, no CA (G8).** On first contact, after the KEM runs, both parties hash the full handshake transcript + both public keys into a **Short Authentication String** (e.g. six words), and compare it once over a human out‑of‑band channel (read it aloud, scan a QR in person). Matching strings rule out a man‑in‑the‑middle with a one‑time human check — **no certificate authority, no central trust.** Back it with a web‑of‑trust if you like.

---

## 10. End‑to‑end lifecycle of one message (Alice → Bob)

1. **(once) Handshake.** Run the Module‑LWE KEM both directions; derive the initial root $rk_0$; confirm the Short Authentication String out‑of‑band.
2. **Field step.** Alice advances the field ratchet → gets $mk_i$, $a_i$; updates transcript hash $H_i$; feeds $a_i$ to the pool.
3. **Pad.** Draw $\ell$ fresh pool bits; $c = \text{plaintext}\oplus\pi_\ell$.
4. **Authenticate.** $\text{tag} = \mathrm{MAC}_{mk_i}(\text{header}_i\,\|\,c)$.
5. **Cell + place.** Pad to fixed cells; encrypt cells; drop at $\mathrm{addr}_j$ amid the constant chaff stream.
6. **Bob mirrors** the field step, recomputes $mk_i$ and the pad, checks the tag (reject on mismatch), unpads, decrypts.
7. **(every $T$ msgs) Epoch / heal.** Fresh ephemeral KEM both ways → $ss_j$ → braid into $rk_{j+1}$ and the next field chain. Channel post‑compromise‑heals; addresses rotate.

---

## 11. How PLEXUS answers each shortcoming

| Goal | Mechanism | Layer |
|---|---|---|
| G1 quantum resistance | Module‑LWE KEM (lattice geometry, Shor‑immune) | L1 |
| G2 OTP secrecy w/o OTP logistics | locally‑synced entropy pool; optional true‑OTP | L3 |
| G3 key distribution | KEM bootstrap + ratchet | L1/L2 |
| G4 forward secrecy | per‑message field ratchet, keys wiped | L2 |
| G5 post‑compromise self‑healing | periodic lattice ratchet | L2 |
| G6 metadata | fixed cells + chaff + rendezvous addresses | L5 |
| G7 deniability | MAC (not signature) + key release | L6 |
| G8 no central trust | Short Authentication String / web‑of‑trust | L6 |

No widely deployed protocol covers this whole column at once. That's the point.

---

## 12. Suggested starting parameters

- **Lattice:** $n=256$, $q=3329$, module rank $k=3$, $\eta=2$ → roughly AES‑192‑class post‑quantum security. Scale $k$ up for more.
- **Sponge:** prime field $p\approx 2^{64}$ (or work in $\mathbb{F}_{2^{64}}$), state width $t=12$, S‑box exponent $\alpha=5$, ~8 full + ~57 partial rounds (tune to your cryptanalysis margin).
- **Braid:** epoch length $T=64$ messages (or 30 s), whichever first.
- **Skin:** 512‑byte cells; ~1 cell/250 ms constant rate with chaff fill.

*(Treat these as a starting point for analysis, not gospel — see §14.)*

---

## 13. What's genuinely novel vs. standing on giants (full honesty)

**Yours / new — the composition:**
1. **The braid** — a dual ratchet where a fast field chain and a periodic lattice chain *cross‑condition* each other and are both bound to a woven transcript hash, giving cheap simultaneous forward + post‑compromise security with explicit splice/reorder resistance.
2. **The spanning entropy‑pool pad** — one mechanism that is a computational OTP by default and becomes a *true* information‑theoretic OTP when fed a real‑entropy budget, on the same live channel.
3. **Ratchet‑derived rendezvous addressing** — reusing root‑key state to generate unlinkable, self‑rotating mailbox addresses, folding metadata unlinkability into the key schedule for free.
4. The unified parameterization and single‑permutation symmetric core tying it all together.

**Giants you're standing on (deliberately, for safety):**
- Module‑LWE / lattice KEMs and the Fujisaki–Okamoto transform (post‑quantum foundation).
- Algebraic sponge permutations (Poseidon/Rescue family) and the sponge/duplex construction.
- The ratchet *idea* (symmetric chains + asymmetric healing) and post‑quantum ratchets that already exist.
- MAC‑based deniability and Short‑Authentication‑String identity (à la OTR / ZRTP).

Reusing these on purpose is the **strength**, not a cop‑out: it means PLEXUS rests on math the world has spent years failing to break, while the *architecture* — the part that is yours — is where the originality lives.

---

## 14. The non‑negotiable caveat, and how to harden this

**Do not protect real people from real adversaries with any unaudited cryptosystem — including this one — yet.** Every serious protocol earns trust through adversarial scrutiny, not elegance. To take PLEXUS from "beautiful design" to "deployable":

1. **Write formal security games** and reduction proofs (IND‑CCA2, forward secrecy, post‑compromise security, deniability) tying each property to its underlying assumption.
2. **Commission independent cryptanalysis** of the braid composition and the chosen sponge parameters.
3. **Build a constant‑time reference implementation** (the NTT and algebraic S‑box are both constant‑time‑friendly — but timing/side channels must be tested, not assumed).
4. **Pin down state‑synchronization** under loss/reorder (define exactly how the entropy‑pool pointer and ratchets re‑sync after dropped cells) and **rate‑limit / bound** dropped‑message skipping.
5. **Publish it** and invite attack. A protocol no one has tried to break is not "secure" — it's "untested."

Natural next steps for the project: formalize a security game for the braid,
write a cryptanalysis attack-surface document, and pressure-test individual
design choices. Contributions and review are welcome — see `CONTRIBUTING.md`.

---

*PLEXUS — a braided, post-quantum, metadata-resistant communication protocol.*
*Copyright (c) 2026 Ideatrino <ideatrino@proton.me>.
