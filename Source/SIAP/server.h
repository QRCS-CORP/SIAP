/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef SIAP_SERVER_H
#define SIAP_SERVER_H

#include "siap.h"

/**
* \file server.h
* \brief SIAP Server functions.
*/

/**
 * \brief Authenticate a device.
 * This function hashes a passphrase, decrypts a device keys token-tree, gets the next authentication token,
 * generates a server token, and authenticates the device.
 *
 * \param dtok The pointer to the output device token.
 * \param dkey The pointer to the device key.
 * \param dtag The pointer to the device tag.
 * \param skey [const] The input server derivation key.
 * \param phash [const] The user passphrase hash.
 */
SIAP_EXPORT_API siap_errors siap_server_authenticate_device(uint8_t* dtok, siap_device_key* dkey, siap_device_tag* dtag, const siap_server_key* skey, const uint8_t* phash);

/**
 * \brief Decrypt a device key.
 * This function decrypts a device keys token-tree.
 *
 * \param dkey The pointer to the output device key.
 * \param skey [const] The input server derivation key.
 * \param phash [const] The passphrase hash.
 */
SIAP_EXPORT_API bool siap_server_decrypt_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash);

/**
 * \brief Encrypt a device key.
 * This function encrypts a device keys token-tree.
 *
 * \param dkey The pointer to the output device key.
 * \param skey [const] The input server derivation key.
 * \param phash [const] The passphrase hash.
 */
SIAP_EXPORT_API void siap_server_encrypt_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash);

/**
 * \brief Extract an authentication token.
 * This function extracts an authentication token and erases it on the tree.
 *
 * \param token The output authentication token.
 * \param dkey The pointer to the output device key.
 * \param skey [const] The input server derivation key.
 */
SIAP_EXPORT_API bool siap_server_extract_authentication_token(uint8_t* token, siap_device_key* dkey, const siap_server_key* skey);

/**
 * \brief Generate an authentication token that matches the device tags token index.
 * This function generates an authentication token using the server key and the device tag.
 *
 * \param token The output authentication token.
 * \param dtag [const] The input device tag.
 * \param skey [const] A pointer to the server key structure.
 */
SIAP_EXPORT_API bool siap_server_generate_authentication_token(uint8_t* token, const siap_device_tag* dtag, const siap_server_key* skey);

/**
 * \brief Generate a device key.
 * This function generates a new SIAP device key using the provided server key.
 * It derives the device key from the server key and sets the key identity and expiration time.
 *
 * \param dkey A pointer to the SIAP device key structure.
 * \param skey [const] A pointer to the SIAP server key structure.
 * \param did [const] The key identity array.
 */
SIAP_EXPORT_API void siap_server_generate_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* did);

/**
 * \brief Generate a device tag.
 * This function generates a new SIAP device tag structure.
 * It populates the provided device tag structure with the device key identity array and a hash of the device key..
 *
 * \param dtag A pointer to the SIAP device tag structure.
 * \param dkey [const] A pointer to the device key.
 * \param phash A pointer to the passphrase hash.
 */
SIAP_EXPORT_API void siap_server_generate_device_tag(siap_device_tag* dtag, const siap_device_key* dkey, const uint8_t* phash);

/**
 * \brief Generate a server key-set.
 * This function generates a new SIAP server key-set based on the provided master key. It populates the server key structure
 * with a derived server key and sets the key identity and expiration time.
 *
 * \param skey A pointer to the SIAP server key structure.
 * \param sid [const] The key identity array.
 *
 * \return Returns false if the random generator fails; otherwise, returns true.
 */
SIAP_EXPORT_API bool siap_server_generate_server_key(siap_server_key* skey, const uint8_t* sid);

/**
 * \brief Generate a readable pseudo-random passphrase.
 *
 * \param passphrase A pointer to the passphrase array.
 * \param length The passphrase length.
 */
SIAP_EXPORT_API void siap_server_passphrase_generate(char* passphrase, size_t length);

/**
 * \brief Generate the passphrase hash.
 *
 * \param phash A pointer to the passphrase hash.
 * \param passphrase [const] A pointer to the passphrase.
 * \param passlen The passphrase length.
 */
SIAP_EXPORT_API void siap_server_passphrase_hash_generate(uint8_t* phash, const char* passphrase, size_t passlen);

/**
 * \brief Verify a passphrase against the hash.
 *
 * \param phash [const] A pointer to the passphrase hash.
 * \param passphrase [const] A pointer to the passphrase.
 * \param passlen The passphrase length.
 *
 * \return Returns true if the passphrase hash matches.
 */
SIAP_EXPORT_API bool siap_server_passphrase_hash_verify(const uint8_t* phash, const char* passphrase, size_t passlen);

/**
 * \brief Hash the key tree and compare it with the value stored in the device tag.
 *
 * \param dtag A pointer to the SIAP device tag structure.
 * \param dkey [const] A pointer to the device key.
 *
 * \return Returns true if the tag hash matches.
 */
SIAP_EXPORT_API bool siap_server_verify_device_tag(siap_device_tag* dtag, const siap_device_key* dkey);

#endif
