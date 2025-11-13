#ifndef SIAP_DOXYMAIN_H
#define SIAP_DOXYMAIN_H

/**
 * \mainpage Secure Infrastructure Access Protocol (SIAP)
 *
 * \section introduction Introduction
 *
 * The Secure Infrastructure Access Protocol (SIAP) is a post-quantum,
 * two-factor authentication framework based entirely on symmetric
 * cryptography. SIAP enables strong identity assurance using a removable
 * memory token containing an encrypted one-time key-tree, combined with a
 * user passphrase hardened through a SHAKE-based cost-amplified function.
 *
 * SIAP eliminates reliance on public-key infrastructures, certificate
 * authorities, or online validation services. All authentication material
 * is derived deterministically from Keccak-family functions without
 * asymmetric operations, allowing secure authentication in offline or
 * resource-constrained environments.
 *
 * SIAP is optimized for secure workstation access, encrypted storage
 * unlock, embedded industrial deployments, and field-service authentication.
 * Its design emphasizes deterministic security, forward secrecy through
 * token consumption, and robust protection against offline dictionary
 * attacks.
 *
 * \section problem Statement of the Problem
 *
 * Conventional authentication systems—including PKI-backed identity
 * frameworks, smart-card infrastructures, and network-mediated trust
 * validation—require consistent connectivity, certificate lifecycle
 * management, or complex cryptographic machinery. These systems present
 * challenges in environments where:
 *
 * - Devices operate offline or under intermittent connectivity.
 * - Certificate issuance, revocation, or validation is impractical.
 * - Long-term independence from asymmetric cryptography is required.
 * - Minimal attack surface and deterministic behaviors are mandatory.
 *
 * In such settings, public-key-based identity systems incur performance,
 * logistical, and operational burdens. SIAP was created to provide a
 * symmetric, verifiable, and forward-secure alternative for environments
 * where asymmetric mechanisms are undesirable or unavailable.
 *
 * \section siap_solution The SIAP Solution
 *
 * SIAP uses a deterministic, single-branch key-tree stored on a memory
 * token. Each leaf of the tree is a unique one-time authentication token
 * generated from the server’s master derivation key (*K_base*) using
 * SHAKE-based expansion and a composite identity string (*Kid*). The
 * tree is encrypted under an AEAD stream cipher (RCS) using a key derived
 * from the user’s passphrase hash and the server salt.
 *
 * Authentication proceeds in three stages:
 *
 * - **Decryption and Verification:** The server verifies expiration,
 *   validates the passphrase by recomputing the SCB hash, decrypts the
 *   token-tree under RCS, and confirms its integrity using a SHAKE-based
 *   state hash.
 *
 * - **Token Extraction:** The server extracts the next unused token
 *   from the key-tree and erases it, advancing the counter encoded in
 *   the *Kid* identity field. This ensures that each token is consumed
 *   exactly once.
 *
 * - **Server-Side Regeneration:** The server recomputes the expected
 *   authentication token using *K_base*, the protocol configuration
 *   string, and the updated *Kid*. Authentication succeeds only if the
 *   extracted and regenerated tokens are identical.
 *
 * After successful authentication, the updated token-tree is re-encrypted
 * and written back to the removable device. This guarantees forward
 * secrecy and prevents replay or rollback of previous token states.
 *
 * \section hierarchy Key-Tree Structure
 *
 * SIAP uses a deterministic key-tree containing 1024 authentication
 * tokens. Each token is derived from:
 *
 *   \f[
 *      K_i = \mathrm{cSHAKE}(K_\mathrm{base}, \mathrm{conf}, \mathrm{Kid}_i)
 *   \f]
 *
 * where the identity string *Kid* incorporates the domain ID, server
 * group ID, server ID, user group ID, user ID, device ID, and the
 * monotonic counter identifying the token index.
 *
 * The key-tree is protected through authenticated encryption using RCS.
 * The passphrase hash (*H_pass*) is computed from a cost-amplified SCB
 * function, mitigating offline dictionary attacks. A SHAKE-based hash
 * of the plaintext key-tree (*H_tree*) binds the device-tag to the
 * current state of the key-tree, ensuring that any modification, rollback,
 * or tampering results in deterministic rejection.
 *
 * \section advantages Advantages of SIAP
 *
 * - **Entirely Symmetric and Post-Quantum:** All security derives from
 *   SHAKE-256/512, cSHAKE, and RCS. No asymmetric primitives are used.
 * - **Two-Factor Security:** The memory token and passphrase must both
 *   be correct before any token is decrypted.
 * - **Forward Secrecy by Consumption:** Each authentication token is
 *   used exactly once and is erased immediately after extraction.
 * - **Replay and Rollback Resistance:** State hashes and counter-bound
 *   key derivations detect any cloned or stale device states.
 * - **Offline Operation:** No certificate validation, server lookup,
 *   or PKI mechanism is necessary.
 * - **Low Implementation Complexity:** Compact, deterministic, and
 *   MISRA-aligned code suitable for embedded and industrial systems.
 *
 * \section applications Applications
 *
 * SIAP is suitable for:
 *
 * - Workstation login and secure local authentication.
 * - Access to encrypted drives or vaults requiring offline identity
 *   verification.
 * - Field-service authentication where devices cannot depend on network
 *   trust infrastructures.
 * - Embedded systems with hardware-enrolled identifiers and symmetric
 *   trust anchors.
 * - Industrial or SCADA environments requiring deterministic and
 *   verifiable authentication without asymmetric cost.
 *
 * \section conclusion Conclusion
 *
 * SIAP provides a robust, symmetric, and post-quantum authentication
 * protocol suitable for offline and highly regulated environments. Its
 * one-time token-tree design, SCB-hardened passphrase hashing, and
 * deterministic Keccak-based derivations provide verifiable forward
 * secrecy, rollback resistance, and strong protection against offline
 * brute-force attacks. By operating without PKI, asymmetric exchanges,
 * or online dependency, SIAP offers a practical and secure authentication
 * mechanism with predictable performance and a minimal attack surface.
 *
 * \section license_sec License
 *
 * QRCS-PL private license. See license file for details.
 * All rights reserved by QRCS Corporation; copyrighted
 * and patents pending.
 *
 * \author John G. Underhill
 * \date 2025-11-04
 */

#endif
