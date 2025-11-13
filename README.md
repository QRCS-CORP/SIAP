# SIAP – Secure Infrastructure Access Protocol

## Introduction

[![Build](https://github.com/QRCS-CORP/SIAP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SIAP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SIAP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SIAP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/siap/badge)](https://www.codefactor.io/repository/github/qrcs-corp/siap)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SIAP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/SIAP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SIAP/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/SIAP)](https://github.com/QRCS-CORP/SIAP/releases/tag/2025-11-12)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SIAP.svg)](https://github.com/QRCS-CORP/SIAP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Secure%20Infrastructure&color=brightgreen)](#)

**SIAP: A Hash-Centric, Post-Quantum, Forward-Secret Two-Factor Authentication Protocol**  
*A zero-certificate access mechanism that combines a memory card and a pass-phrase to authorize logins, decrypt storage, and key symmetric channels.*

[SIAP Help Documentation](https://qrcs-corp.github.io/SIAP/)  
[SIAP Protocol Specification](https://qrcs-corp.github.io/SATP/pdf/siap_specification.pdf)  
[SIAP Summary Document](https://qrcs-corp.github.io/SATP/pdf/siap_summary.pdf)

## Overview

SIAP is a drop-in replacement for password or static key-based authentication in environments where **PKI is impractical, post-quantum security is required, or infrastructure operates offline**.

* **Post-Quantum Security** – Built entirely on SHA-3-family primitives and the memory-hard `SCB` KDF.  
* **Forward-Secrecy-by-Consumption** – Each session burns a one-time leaf key; keys cannot be reused, rewound, or derived once erased.  
* **Two-Factor Authentication** – Possession of a memory access card plus a pass-phrase required for every session.  
* **Zero Certificates** – Plain-text identity headers replace X.509, CRLs, and CA maintenance.  
* **Tiny Footprint** – ≤ 30 kB flash / ≤ 4 kB RAM; fits smart cards, USB tokens, or low-cost microcontrollers.  
* **Offline-Ready** – Fully deterministic authentication with no network dependencies.

## 2  Cryptographic Core

| Primitive              | Role                                | Quantum Margin                 |
|------------------------|-------------------------------------|--------------------------------|
| **SHAKE-256**          | Identity hashing and leaf derivation| ≥ 2¹²⁸ pre-image (Grover-bounded) |
| **SCB-KDF**            | Pass-phrase hardening               | ≥ 2²⁰ CPU·MiB per guess        |
| **KMAC-256** (optional)| Message authentication              | Tag-forgery ≤ 2⁻¹²⁸            |
| **RCS-256** (optional) | AEAD for payload or channel cipher  | ≥ 2¹²⁸ Grover-bounded          |

## 3 Deployment Snapshots

### 3.1 PCI DSS 4.0 MFA Access Control  
Jump-host logins trigger SIAP token use; 65 k unique leaf keys per card, no HSMs or PKI required.

### 3.2 Offline CBDC Wallets  
Card holds 15 k one-time keys; POS terminal verifies leaf with SHAKE and burns it locally. No certs or re-connect needed.

### 3.3 Field Technician Access  
Each device verifies its own `Kbase` and token `Kidx`. No VPN or remote login required.

### 3.4 Cold-Wallet Signing Ceremonies  
Tokens deliver one leaf per withdrawal; custodian vault rotates tokens quarterly; past leaves unrecoverable.

### 3.5 OEM Secure-Boot Keys  
Factory cards embed key-tree; each firmware decrypt burns a key. Line stops when exhausted.

### 3.6 PSK Injection for TLS/IKE  
Proxy or tunnel calls SIAP token for a 256-bit PSK; supports 0-RTT channel startup.

### 3.7 SCADA/HMI Local Login  
Token authorizes local GUI unlock in air-gapped settings. Audit log increments on every use.

## Compilation

SIAP uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer  
- **Windows**: Visual Studio 2022 or newer  
- **macOS**: Clang via Xcode or Homebrew  
- **Ubuntu**: GCC or Clang  

### Building SIAP library and the Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the Server and Client projects: SIAP, Server, and Client.  
Extract the files, and open the Server and Client projects. The SIAP library has a default location in a folder parallel to the Server and Client project folders.  
Update include paths: **$(SolutionDir)SIAP** and **$(SolutionDir)..\QSC\QSC**  
Ensure that each project references the SIAP and QSC libraries and uses the same AVX setting:  
**Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**  

Compile QSC, then SIAP, then the Server and Client projects.

#### MacOS / Ubuntu (Eclipse)

Eclipse project files are provided for Ubuntu and macOS in respective folders.  
Copy `.project`, `.cproject`, and `.settings` files into each project directory.  
Create empty C/C++ projects in Eclipse with matching names.  
Set build flags to match your platform; by default, No Enhanced Intrinsics are used.

Sample AVX flags:
- AVX: `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2`  
- AVX2: `-msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2`  
- AVX-512: `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes`

## License

ACQUISITION INQUIRIES:  
QRCS is currently seeking a corporate acquirer for this technology.  
Parties interested in exclusive licensing or acquisition should contact: contact@qrcscorp.ca

PATENT NOTICE:  
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and  
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and SIAP is patent pending.  
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details.  
Not to be redistributed or used commercially without the author's expressed written permission.  
_All rights reserved by QRCS Corp. 2025._
