# SIAP — Secure Infrastructure Access Protocol

[![Build](https://github.com/QRCS-CORP/SIAP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SIAP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SIAP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SIAP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/siap/badge)](https://www.codefactor.io/repository/github/qrcs-corp/siap)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SIAP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/SIAP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SIAP/)
[![Release](https://img.shields.io/github/v/release/QRCS-CORP/SIAP)](https://github.com/QRCS-CORP/SIAP/releases/tag/2025-11-12)
[![Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SIAP.svg)](https://github.com/QRCS-CORP/SIAP/commits/main)
[![Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Secure%20Infrastructure&color=brightgreen)](#)

> **A hash-centric, post-quantum, forward-secret two-factor authentication protocol.**  
> A zero-certificate access mechanism combining a memory card and a passphrase to authorize logins, decrypt storage, and key symmetric channels.

---

## Table of Contents

1. [Overview](#overview)
2. [Key Properties](#key-properties)
3. [Cryptographic Core](#cryptographic-core)
4. [Quick Start](#quick-start)
5. [How It Works](#how-it-works)
6. [Deployment Examples](#deployment-examples)
7. [Building SIAP](#building-siap)
8. [Documentation](#documentation)
9. [License](#license)

---

## Overview

SIAP is a drop-in replacement for password- or static-key-based authentication in environments where **PKI is impractical, post-quantum security is required, or infrastructure operates offline or air-gapped**.

Instead of certificates, CAs, or symmetric PSKs negotiated in the clear, SIAP provides authentication through two independently verifiable factors:

- **Something you have** — a memory card (USB token, smart card, or file) holding a pre-generated tree of 1,024 one-time leaf keys.
- **Something you know** — a passphrase that encrypts the key tree at rest and binds authentication to the holder.

Every successful login burns exactly one leaf key. A burned leaf cannot be recovered, replayed, or reused — even by an attacker who subsequently obtains the card.

---

## Key Properties

| Property | Detail |
|---|---|
| **Post-quantum security** | Built entirely on SHA-3 family primitives (SHAKE-256, cSHAKE-256, KMAC-256). No elliptic curves. No RSA. |
| **Forward secrecy by consumption** | Each session burns a one-time leaf key. Past sessions remain secure even if the card is later stolen. |
| **Two-factor authentication** | Card possession + passphrase required. Neither alone is sufficient. |
| **Zero certificates** | Plain-text identity headers replace X.509, CRLs, and CA infrastructure. |
| **Tiny footprint** | ≤ 30 kB flash / ≤ 4 kB RAM. Fits smart cards, USB tokens, and low-cost microcontrollers. |
| **Offline-ready** | Fully deterministic authentication. No network connectivity required at verification time. |
| **MISRA-C aligned** | Codebase targets safety-critical coding standards throughout. |

---

## Cryptographic Core

| Primitive | Role | Quantum Security Margin |
|---|---|---|
| **SHAKE-256** | Identity hashing and leaf key derivation | ≥ 2¹²⁸ (Grover-bounded pre-image) |
| **cSHAKE-256** | Domain-separated key tree generation | ≥ 2¹²⁸ |
| **SCB-KDF** | Passphrase hardening (memory-hard) | ≥ 2²⁰ CPU·MiB per guess |
| **KMAC-256** *(optional)* | Message authentication | Tag-forgery probability ≤ 2⁻¹²⁸ |
| **RCS-256** *(optional)* | AEAD for payload or symmetric channel | ≥ 2¹²⁸ (Grover-bounded) |

The key tree is generated deterministically on the server using `cSHAKE-256(K_base, config_string, device_id || index)`. The server never needs to store the plaintext tree — it can re-derive any leaf at any index on demand. The device key file stores the full tree, encrypted and MAC-protected under a key derived from the user passphrase and a per-server salt.

---

## Quick Start

The reference implementation can be run on a single machine to explore enrollment and authentication end-to-end.

### First Run — Server Initialization

On the very first launch the server detects no existing key material and walks through a guided setup. The session below shows the complete enrollment process:

```
server> The server-key was not detected, generating new server/device keys.

server> Enter a 32 character hexadecimal server/device key identity, ex.
        000102030405060708090A0B0C0D0E0F

server> 000102030405060708090A0B0C0D0E0F

server> The server-key has been saved to:
        C:\Users\user\Documents\SIAP\srvkey.skey

server> The user passphrase has been generated:
        >Rr|$0VuWV(dV&b5B?eDb)z#Pj,r,R9y

server> The database has been saved to:
        C:\Users\user\Documents\SIAP\user.db

server> The device-key has been saved to:
        C:\Users\user\Documents\SIAP\devkey.skey

server> Distribute the device-key to the intended client.

server> Success! The server and device keys have been created, restart to test.
server> Press any key to close...
```

**What happened, step by step:**

1. **Identity input** — You supply a 16-byte (32 hex character) server/device identity. This becomes the domain identifier embedded in every key derived for this server. It binds all device keys cryptographically to this specific server identity.

2. **Server key generation** — A 256-bit master key (`K_base`) is generated from the platform CSPRNG (`ACP`). A per-server salt is derived as `cSHAKE-256(K_base, config, server_id)`. Together these form `srvkey.skey` — the root secret that never leaves the server.

3. **Passphrase generation** — A high-entropy printable passphrase is generated for the user. This passphrase is hashed through the memory-hard **SCB-KDF** and the resulting hash is used to encrypt the device key tree. The server stores only the hash, never the passphrase itself.

4. **Device key generation** — A tree of 1,024 one-time authentication tokens is derived as `cSHAKE-256(K_base, config, device_id || index)` for each index 0–1023. The tree is encrypted with RCS-256 under a key derived from `cSHAKE-256(passphrase_hash, device_id, server_salt)` and saved as `devkey.skey`.

5. **Distribution** — `devkey.skey` is the file to transfer to the client device (USB stick, secure copy, etc.). The server retains `srvkey.skey` and `user.db`. After distribution, restart the server and the client can authenticate immediately.

> **Security note:** The passphrase shown above is generated once and displayed once. Record it securely before closing the terminal — it is not stored anywhere and cannot be recovered. If lost, the device key must be regenerated and redistributed.

### Subsequent Authentication

Once both sides hold their respective key files, authentication proceeds automatically. The client presents the current leaf token from `devkey.skey`; the server independently derives the same token from `srvkey.skey` and the known index, compares them in constant time, burns the leaf on both sides, and advances the counter. No network round-trip for key exchange is needed.

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────────┐
│                        ENROLLMENT (once)                            │
│                                                                     │
│  Server                           Client / Device Card              │
│  ──────────────────────           ─────────────────────────         │
│  Generate K_base (CSPRNG)                                           │
│  Derive server salt                                                 │
│  Generate 1024 leaf keys ──────── Encrypted key tree (devkey.skey) │
│  Store srvkey.skey + user.db      Store passphrase securely         │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      AUTHENTICATION (each session)                  │
│                                                                     │
│  Client                           Server                            │
│  ──────────────────────           ─────────────────────────         │
│  Decrypt key tree with passphrase                                   │
│  Read leaf[kidx] ─────────────── Derive leaf[kidx] from K_base     │
│  Erase leaf[kidx] locally        Compare in constant time           │
│  Increment kidx                   Burn kidx; advance counter        │
│  Save devkey.skey                 Save updated user.db              │
└─────────────────────────────────────────────────────────────────────┘
```

The server never stores leaf keys in plaintext. It re-derives the expected leaf on demand using the server master key and the current index. Because derivation is deterministic, the server and client remain synchronized as long as each successful authentication increments both counters.

**What an attacker gains from stealing the card without the passphrase:** An encrypted blob. The key tree is protected by RCS-256 authenticated encryption keyed from `cSHAKE-256(SCB(passphrase), device_id, server_salt)`. Without the passphrase, the tree is computationally inaccessible.

**What an attacker gains from a network intercept:** A single-use token that is already burned by the time it can be replayed.

**What an attacker gains from the server database:** The server stores only the passphrase *hash* (SCB output) and the current index. Reversing the SCB hash to recover the passphrase requires ≥ 2²⁰ CPU·MiB operations per guess.

---

## Deployment Examples

### PCI DSS 4.0 — Jump-Host MFA
SIAP replaces soft-token MFA on jump servers. Up to 1,024 unique leaf keys per card; no HSMs, no PKI, no RADIUS dependency. Each privileged session burns one leaf.

### Offline CBDC Wallets
A card holds 1,024 one-time keys. A POS terminal verifies the current leaf using SHAKE-256 and burns it locally. No certificate validation, no connectivity required at point of sale.

### Field Technician Device Access
Each device verifies its own `K_base` and token index. Technicians authenticate with card + passphrase to unlock firmware update interfaces in air-gapped environments.

### Cold-Wallet Signing Ceremonies
One leaf per withdrawal authorization. Custodian vaults rotate cards quarterly. All consumed leaves are mathematically unrecoverable — there is no rollback.

### OEM Secure-Boot Key Delivery
Factory programming cards embed a key tree. Each firmware decryption burns one key. When the tree is exhausted, the production line stops automatically — preventing unauthorized over-build.

### PSK Injection for TLS/IKE
A proxy calls SIAP for a fresh 256-bit PSK per session, enabling 0-RTT channel startup without static pre-shared keys or certificate exchange.

### SCADA / HMI Local Login
Token authorizes local GUI unlock in air-gapped control networks. Every authentication event appends an immutable entry to the audit log.

---

## Building SIAP

SIAP depends on the **QSC cryptographic library** — a standalone, portable, MISRA-aligned C library with hardware-acceleration support (AES-NI, AVX2/AVX-512, RDRAND) across Windows, macOS, and Linux.

### Prerequisites

| Platform | Toolchain |
|---|---|
| Windows | Visual Studio 2022 or newer + CMake 3.15+ |
| macOS | Clang via Xcode or Homebrew + CMake 3.15+ |
| Linux (Ubuntu) | GCC or Clang + CMake 3.15+ |

### Windows (Visual Studio)

1. Extract SIAP and QSC into sibling directories, e.g.:
   ```
   workspace/
   ├── QSC/
   └── SIAP/
   ```
2. Open the SIAP solution in Visual Studio 2022.
3. Verify include paths in project properties:
   - `$(SolutionDir)SIAP`
   - `$(SolutionDir)..\QSC\QSC`
4. Ensure all projects share the same **Enhanced Instruction Set** setting under `Configuration Properties → C/C++ → All Options`.
5. Build in order: **QSC → SIAP → Server → Client**.

### macOS / Linux (Eclipse or CMake)

Eclipse project files are provided in the `macos/` and `ubuntu/` directories. Copy `.project`, `.cproject`, and `.settings` into each project directory, then create matching empty C/C++ projects in Eclipse.

Set SIMD build flags to match your target CPU:

```bash
# AVX (baseline)
-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2

# AVX2
-msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2

# AVX-512
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes
```

> If deploying to a platform without AVX support (e.g., embedded targets or older servers), use the scalar build with no enhanced intrinsics flags.

---

## Documentation

| Resource | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/SIAP/) | Full API reference and integration guide |
| [Summary Document](https://qrcs-corp.github.io/SIAP/pdf/siap_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/SIAP/pdf/siap_specification.pdf) | Formal message formats and state machine |
| [Formal Analysis](https://qrcs-corp.github.io/SIAP/pdf/siap_formal.pdf) | Symbolic and computational security proofs |
| [Implementation Analysis](https://qrcs-corp.github.io/SIAP/pdf/siap_analysis.pdf) | Code-level security review and notes |

---

## License

This repository is published under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**.

**Permitted uses:** Non-commercial evaluation, academic research, cryptographic analysis, interoperability testing, and feasibility assessment.

**Not permitted without a separate written agreement:** Production deployment, commercial use, or incorporation into any product or service.

> **Patent notice:** One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact: [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca)

For commercial licensing inquiries: [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)

Visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of products and services.

---

*© 2025–2026 Quantum Resistant Cryptographic Solutions Corporation. All rights reserved.*
