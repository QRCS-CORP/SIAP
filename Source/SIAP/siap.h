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

#ifndef SIAP_H
#define SIAP_H

#include "siapcommon.h"
#include "logger.h"
#include "sha3.h"
#include "socket.h"
#include "socketclient.h"

/**
* \file siap.h
* \brief SIAP support header
* Common defined parameters and functions of the SIAP client and server implementations.
*/

/*!
* \def SIAP_EXTENDED_ENCRYPTION
* \brief Ebable 512-bit symmetric encryption.
*/
//#define SIAP_EXTENDED_ENCRYPTION

/*!
* \def SIAP_CLIENT_PASSWORD_MAX
* \brief The client passphrase maximum string length
*/
#define SIAP_CLIENT_PASSWORD_MAX 256U

/*!
* \def SIAP_CLIENT_USERNAME_MAX
* \brief The client username maximum string length
*/
#define SIAP_CLIENT_USERNAME_MAX 256U

/*!
* \def SIAP_CONFIG_SIZE
* \brief The size of the protocol configuration string.
*/
#define SIAP_CONFIG_SIZE 26U

/*!
* \def SIAP_DEVICE_ID_SIZE
* \brief Key card device ID size in bytes.
*/
#define SIAP_DEVICE_ID_SIZE 4U

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_AUTHENTICATION_TOKEN_SIZE
* \brief The client key size in bytes.
*/
#	define SIAP_AUTHENTICATION_TOKEN_SIZE 64U
#else
/*!
* \def SIAP_AUTHENTICATION_TOKEN_SIZE
* \brief The client key size in bytes.
*/
#	define SIAP_AUTHENTICATION_TOKEN_SIZE 32U
#endif

/*!
* \def SIAP_DOMAIN_ID_SIZE
* \brief Domain (Master) ID size in bytes.
*/
#define SIAP_DOMAIN_ID_SIZE 2U

/*!
* \def SIAP_ERROR_SIZE
* \brief The size of a system error message.
*/
#define SIAP_ERROR_SIZE 1U

/*!
* \def SIAP_EXPIRATION_SIZE
* \brief The size (in bytes) of the expiration field.
*/
#define SIAP_EXPIRATION_SIZE 8U

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_HASH_SIZE
* \brief The SIAP hash size in bytes.
*/
#	define SIAP_HASH_SIZE 64U
#else
/*!
* \def SIAP_HASH_SIZE
* \brief The SIAP hash size in bytes.
*/
#	define SIAP_HASH_SIZE 32U
#endif

/*!
* \def SIAP_KEY_DURATION_DAYS
* \brief The number of days a key remains valid.
*/
#define SIAP_KEY_DURATION_DAYS 365U

/*!
* \def SIAP_KEY_DURATION_SECONDS
* \brief The number of seconds a key remains valid.
*/
#define SIAP_KEY_DURATION_SECONDS (SIAP_KEY_DURATION_DAYS * 24U * 60U * 60U)

/*!
* \def SIAP_KEY_ID_SIZE
* \brief User key ID size in bytes.
*/
#define SIAP_KEY_ID_SIZE 4U

/*!
* \def SIAP_KTREE_COUNT
* \brief The SIAP key tree count.
*/
#define SIAP_KTREE_COUNT 1024

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_KTAG_STATE_HASH
* \brief The client key state hash size.
*/
#	define SIAP_KTAG_STATE_HASH 64U
#else
/*!
* \def SIAP_KTAG_STATE_HASH
* \brief The client key state hash size.
*/
#	define SIAP_KTAG_STATE_HASH 32U
#endif

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_MAC_SIZE
* \brief The SIAP MAC size in bytes.
*/
#	define SIAP_MAC_SIZE 64U
#else
/*!
* \def SIAP_MAC_SIZE
* \brief The SIAP MAC size in bytes.
*/
#	define SIAP_MAC_SIZE 32U
#endif

/*!
* \def SIAP_NONCE_SIZE
* \brief The nonce size.
*/
#define SIAP_NONCE_SIZE 32U

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_SALT_SIZE
* \brief The SIAP salt size in bytes.
*/
#	define SIAP_SALT_SIZE 64U
#else
/*!
* \def SIAP_SALT_SIZE
* \brief The SIAP salt size in bytes.
*/
#	define SIAP_SALT_SIZE 32U
#endif

/*!
* \def SIAP_SERVER_GROUP_ID_SIZE
* \brief Server Group ID size in bytes.
*/
#define SIAP_SERVER_GROUP_ID_SIZE 2U

/*!
* \def SIAP_SERVER_ID_SIZE
* \brief Server ID size in bytes.
*/
#define SIAP_SERVER_ID_SIZE 2U

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \def SIAP_SERVER_KEY_SIZE
* \brief The master key size in bytes.
*/
#	define SIAP_SERVER_KEY_SIZE 64U
#else
/*!
* \def SIAP_SERVER_KEY_SIZE
* \brief The master key size in bytes.
*/
#	define SIAP_SERVER_KEY_SIZE 32U
#endif

/*!
* \def SIAP_USER_GROUP_ID_SIZE
* \brief User Group ID size in bytes.
*/
#define SIAP_USER_GROUP_ID_SIZE 2U

/*!
* \def SIAP_USER_ID_SIZE
* \brief User ID size in bytes.
*/
#define SIAP_USER_ID_SIZE 4U

/* compound sizes */

/*!
* \def SIAP_DID_SIZE
* \brief The full sub-key ID size in bytes.
*/
#define SIAP_DID_SIZE (SIAP_DOMAIN_ID_SIZE + SIAP_SERVER_GROUP_ID_SIZE + SIAP_SERVER_ID_SIZE + SIAP_USER_GROUP_ID_SIZE + SIAP_USER_ID_SIZE + SIAP_DEVICE_ID_SIZE)

/*!
* \def SIAP_SID_SIZE
* \brief The server ID size in bytes.
*/
#define SIAP_SID_SIZE (SIAP_DOMAIN_ID_SIZE + SIAP_SERVER_GROUP_ID_SIZE + SIAP_SERVER_ID_SIZE)

/*!
* \def SIAP_KID_SIZE
* \brief The tree-key ID size in bytes.
*/
#define SIAP_KID_SIZE (SIAP_DID_SIZE + SIAP_KEY_ID_SIZE)

/*!
* \def SIAP_KTREE_SIZE
* \brief	The key tree size in bytes.
*/
#define SIAP_KTREE_SIZE (SIAP_AUTHENTICATION_TOKEN_SIZE * SIAP_KTREE_COUNT)

/*!
* \def SIAP_DEVICE_KEY_ENCODED_SIZE
* \brief The device key size in bytes.
*/
#define SIAP_DEVICE_KEY_ENCODED_SIZE ((SIAP_AUTHENTICATION_TOKEN_SIZE * SIAP_KTREE_COUNT) + SIAP_MAC_SIZE + SIAP_KID_SIZE + SIAP_EXPIRATION_SIZE)

/*!
* \def SIAP_DEVICE_TAG_ENCODED_SIZE
* \brief The device tag size in bytes.
*/
#define SIAP_DEVICE_TAG_ENCODED_SIZE (SIAP_KID_SIZE + SIAP_KTAG_STATE_HASH + SIAP_HASH_SIZE)

/*!
* \def SIAP_SERVER_KEY_ENCODED_SIZE
* \brief The server key size in bytes.
*/
#define SIAP_SERVER_KEY_ENCODED_SIZE (SIAP_SERVER_KEY_SIZE + SIAP_SID_SIZE + SIAP_SALT_SIZE + SIAP_EXPIRATION_SIZE)

/*!
 * \def SIAP_SCB_CPU_COST
 * \brief The SCB passphrase KDF CPU Cost factor.
 *
 * \details Adjust this parameter according to your hardware and security needs.
 * Benchmark to ensure ~200 ms per hash on the server CPU.
 * Changing this parameter effects the number of total iterations the hash function
 * and memory expansion function undergoes.
 * Recommended no more than 4 on most server security profiles.
 */
#define SIAP_SCB_CPU_COST 1U

/*!
 * \def SIAP_SCB_MEMORY_COST
 * \brief The SCB passphrase KDF Memory Cost factor.
 * 
 * \details Adjust this parameter according to your hardware and security needs.
 * Benchmark to ensure ~200 ms per hash on the server CPU.
 * Recommended no more than 8 on most server security profiles.
 * This parameter is a memory multiplier and effects the amount of memory 
 * allocated by the SCB hashing function
 */
#define SIAP_SCB_MEMORY_COST 1U

/* error code strings */

#if defined(SIAP_EXTENDED_ENCRYPTION)
/*!
* \brief The SIAP configuration string for 256-bit security.
*/
static const char SIAP_CONFIG_STRING[SIAP_CONFIG_SIZE + 1U] = "r01-siap-rcs512-keccak512";
#else
/*!
* \brief The SIAP configuration string for 256-bit security.
*/
static const char SIAP_CONFIG_STRING[SIAP_CONFIG_SIZE + 1U] = "r02-siap-rcs256-keccak256";
#endif

/** \cond */
#define SIAP_ERROR_STRING_DEPTH 13U
#define SIAP_ERROR_STRING_WIDTH 128U

static const char SIAP_ERROR_STRINGS[SIAP_ERROR_STRING_DEPTH][SIAP_ERROR_STRING_WIDTH] =
{
	"The operation was succesful",
	"The authentication has failed",
	"The identity strings do not match",
	"The function received invalid input",
	"The key card has expired",
	"The device passphrase is unrecognized",
	"The cards authentication tokens are invalid",
	"The key card decryption failed",
	"The authentication token is invalid",
	"The server could not generate the token",
	"The file could not be read",
	"The file path specified is invalid",
	"The file is locked or unavailable",
};
/** \endcond */

/*!
 * \enum siap_errors
 * \brief The SIAP error values.
 * This enumeration defines the error codes returned by SIAP functions.
 */
SIAP_EXPORT_API typedef enum siap_errors
{
	siap_error_none = 0x00U,					/*!< The operation was succesful */
	siap_error_authentication_failure = 0x01U,	/*!< The authentication has failed */
	siap_error_identity_mismatch = 0x02U,		/*!< The identity strings do not match */
	siap_error_invalid_input = 0x03U,			/*!< The function received invalid input */
	siap_error_key_expired = 0x04U,				/*!< The key card has expired */
	siap_error_passphrase_unrecognized = 0x05U,	/*!< The device passphrase is unrecognized */
	siap_error_token_tree_invalid = 0x06U,		/*!< The cards authentication tokens are invalid */
	siap_error_decryption_failure = 0x07U,		/*!< The key card decryption failed */
	siap_error_token_invalid = 0x08U,			/*!< The authentication token is invalid */
	siap_error_token_not_created = 0x09U,		/*!< The server could not generate the token */
	siap_error_file_read_failure = 0x0AU,		/*!< The file could not be read */
	siap_error_file_invalid_path = 0x0BU,		/*!< The file path specified is invalid */
	siap_error_file_copy_failure = 0x0CU		/*!< The file is locked or unavailable */
} siap_errors;

/*!
 * \struct siap_device_key
 * \brief The SIAP device key structure.
 * This structure contains the SIAP device key, the device key identity, and expiration time.
 */
SIAP_EXPORT_API typedef struct siap_device_key
{
	uint8_t ktree[SIAP_KTREE_SIZE + SIAP_MAC_SIZE];	/*!< The device token tree */
	uint8_t kid[SIAP_KID_SIZE];					/*!< The key device identity array */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} siap_device_key;

/*!
 * \struct siap_key_tag
 * \brief The SIAP server device tag structure.
 * This structure contains the device key ID, and a hash of the device key.
 */
SIAP_EXPORT_API typedef struct siap_device_tag
{
	uint8_t kid[SIAP_KID_SIZE];					/*!< The key device key identity array */
	uint8_t khash[SIAP_KTAG_STATE_HASH];		/*!< The hash of the device key */
	uint8_t phash[SIAP_HASH_SIZE];				/*!< The passphrase hash */
} siap_device_tag;

/*!
 * \struct siap_server_key
 * \brief The SIAP server key structure.
 * This structure contains the SIAP server key, the server's domain identity, the device key, and expiration time.
 */
SIAP_EXPORT_API typedef struct siap_server_key
{
	uint8_t kbase[SIAP_SERVER_KEY_SIZE];		/*!< The server derivation key */
	uint8_t sid[SIAP_SID_SIZE];					/*!< Server domain ID */
	uint8_t dsalt[SIAP_SALT_SIZE];				/*!< Server device salt */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} siap_server_key;

/**
 * \brief Deserialize a client device key.
 * This function deserializes a byte array into a SIAP device key structure.
 *
 * \param dkey A pointer to the output SIAP device key structure.
 * \param input [const] The input serialized device key array of size \c SIAP_DEVICE_KEY_ENCODED_SIZE.
 */
SIAP_EXPORT_API void siap_deserialize_device_key(siap_device_key* dkey, const uint8_t* input);

/**
 * \brief Serialize a client device key.
 * This function serializes a SIAP device key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized device key array of size \c SIAP_DEVICE_KEY_ENCODED_SIZE.
 * \param dkey [const] A pointer to the input SIAP device key structure.
 */
SIAP_EXPORT_API void siap_serialize_device_key(uint8_t* output, const siap_device_key* dkey);

/**
 * \brief Return a string description of an SIAP error code.
 * This function returns a human-readable string corresponding to the provided SIAP error code.
 *
 * \param error The SIAP error code.
 *
 * \return Returns a pointer to the error description string, or NULL if the error code is not recognized.
 */
SIAP_EXPORT_API const char* siap_error_to_string(siap_errors error);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
*
* \return Returns a pointer to the message string or NULL
*/
SIAP_EXPORT_API const char* siap_get_error_description(siap_errors emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
SIAP_EXPORT_API void siap_log_error(siap_errors emsg, const char* msg);

/*!
* \brief Log a system error message
*
* \param err: The system error enumerator
*/
SIAP_EXPORT_API void siap_log_system_error(siap_errors err);

/**
 * \brief Deserialize a device tag from a byte array.
 * This function deserializes a byte array into a SIAP device tag structure.
 *
 * \param dtag A pointer to the output SIAP device tag structure.
 * \param input [const] The input serialized device tag array of size \c SIAP_DEVICE_TAG_ENCODED_SIZE.
 */
SIAP_EXPORT_API void siap_deserialize_device_tag(siap_device_tag* dtag, const uint8_t* input);

/**
 * \brief Serialize a device tag into a byte array.
 * This function serializes a SIAP device tag structure into a byte array.
 *
 * \param output The output byte array to hold the serialized device tag of size \c SIAP_DEVICE_TAG_ENCODED_SIZE.
 * \param dtag [const] A pointer to the input SIAP device tag structure.
 */
SIAP_EXPORT_API void siap_serialize_device_tag(uint8_t* output, const siap_device_tag* dtag);

/**
 * \brief Deserialize a server key from a byte array.
 * This function deserializes a byte array into a SIAP server key structure.
 *
 * \param skey A pointer to the output SIAP server key structure.
 * \param input [const] The input serialized server key array of size \c SIAP_SERVER_KEY_ENCODED_SIZE.
 */
SIAP_EXPORT_API void siap_deserialize_server_key(siap_server_key* skey, const uint8_t* input);

/**
 * \brief Serialize a server key into a byte array.
 * This function serializes a SIAP server key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized server key of size \c SIAP_SERVER_KEY_ENCODED_SIZE.
 * \param skey [const] A pointer to the input SIAP server key structure.
 */
SIAP_EXPORT_API void siap_serialize_server_key(uint8_t* output, const siap_server_key* skey);

/**
 * \brief Increment the device key
 * This function clears a key at the current position and increments the kid counter.
 *
 * \param dkey [const] A pointer to the input/output SIAP device key structure.
 */
SIAP_EXPORT_API void siap_increment_device_key(siap_device_key* dkey);

#endif
