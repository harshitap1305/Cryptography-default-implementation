# DEFAULT Cipher — IC-DFA Attack Visualization

An interactive, browser-based 3D visualization of the **Information-Combining Differential Fault Attack (IC-DFA)** on the **DEFAULT cipher**, as presented at Eurocrypt 2022 by Nageler et al.

## Overview

DEFAULT is a lightweight block cipher with a "sandwich" architecture that uses two different S-boxes (LS and NLS) across 80 rounds, operating on a 128-bit state with a 128-bit key.

This project simulates and visualizes the full IC-DFA attack pipeline in an 8-step walkthrough, allowing you to observe how fault injections progressively reduce the secret key space from 2¹²⁸ down to a unique solution — all rendered in real-time 3D using Three.js.

## Features

- **3D Cipher Visualization** — Three.js-powered rendering of the DEFAULT cipher's sandwich round structure with bloom post-processing effects
- **Live Attack Simulation** — Step-by-step IC-DFA attack with real cryptographic computations
- **8-Phase Attack Walkthrough:**
  1. **Setup** — Generate a random 128-bit secret key
  2. **Encrypt** — Run the full 80-round DEFAULT encryption
  3. **Fault Injection** — Inject bit-flip faults at targeted cipher rounds and nibbles
  4. **DFA Analysis** — Filter last-round key candidates using the Difference Distribution Table (DDT)
  5. **Equivalence Classes** — Identify key equivalences introduced by the LS S-box linear structures
  6. **Normalization** — Compute canonical representatives for each key nibble
  7. **Information Combining** — Accumulate multiple fault equations to progressively reduce key candidates
  8. **Key Recovery** — Recover the full 128-bit master key
- **Real-time Key Space Gauge** — Visual tracker showing remaining key bits (2¹²⁸ → 1)
- **Nibble Candidate Grid** — 32-nibble display showing per-nibble candidate counts
- **Equation System Monitor** — Tracks rank of the overdetermined system of fault equations
- **Crypto Terminal** — Live log of all intermediate computation steps

## Demo

Open `index.html` directly in any modern browser — no server or build step required.

```
open index.html
```

> Tested in Chrome and Firefox. WebGL must be enabled.

## Repository Structure

```
├── index.html          # Main application — 3D scene, UI layout, and styles
├── attack_engine.js    # IC-DFA simulation engine (cipher, fault injection, DFA)
├── attack_ui.js        # UI controller — orchestrates the 8-step attack animation
├── default_orginal_paper.pdf   # Original DEFAULT cipher specification paper
└── euro_crypt_atatck.pdf       # Eurocrypt 2022 IC-DFA attack paper (Nageler et al.)
```

## Cryptographic Details

### DEFAULT Cipher

| Parameter     | Value                  |
|---------------|------------------------|
| Block size    | 128 bits               |
| Key size      | 128 bits               |
| Rounds        | 80                     |
| Round function | SubCells → PermBits → AddRoundConstants → AddRoundKey |
| S-box (rounds 0–27, 52–79) | LS (linear-structured) |
| S-box (rounds 28–51) | NLS (non-linear-structured) |
| Bit permutation | GIFT-128 P128        |
| Round constants | 6-bit LFSR           |

### IC-DFA Attack

The attack exploits **linear structures** in the LS S-box — input/output XOR pairs `(α, β)` where `S(x) ⊕ S(x ⊕ α) = β` for all `x`. The four linear structures are:

| α   | β   |
|-----|-----|
| `0` | `0` |
| `6` | `A` |
| `9` | `F` |
| `F` | `5` |

These structures create key equivalence classes, reducing the effective key space. By combining fault equations across multiple fault injections, the attack achieves full key recovery with approximately **16 fault measurements**.

**Attack complexity:** The full IC-DFA recovers the 128-bit key from ~16 single-nibble bit-flip faults at round 79 (the last round before output).

## Dependencies

All dependencies are loaded via CDN — no installation needed.

| Library | Version | Purpose |
|---------|---------|---------|
| [Three.js](https://threejs.org/) | r128 | 3D rendering and scene management |
| [GSAP](https://greensock.com/gsap/) | 3.12.2 | UI and camera animations |
| Google Fonts | — | Inter and JetBrains Mono typefaces |

## References

- Nageler, M., Leurent, G., Eichlseder, M., & Rechberger, C. (2022). **Information-Combining Differential Fault Attacks on DEFAULT**. *Eurocrypt 2022*.
- Original DEFAULT cipher paper included as `default_orginal_paper.pdf`.
- Attack paper included as `euro_crypt_atatck.pdf`.
