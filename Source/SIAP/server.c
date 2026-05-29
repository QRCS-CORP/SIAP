#include "server.h"
#include "acp.h"
#include "async.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "rcs.h"
#include "scb.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

static void siap_server_seal_info(uint8_t* info, const siap_device_key* dkey)
{
	qsc_memutils_copy(info, SIAP_SEAL_LABEL, SIAP_SEAL_LABEL_SIZE);
	qsc_memutils_copy(info + SIAP_SEAL_LABEL_SIZE, dkey->kid, SIAP_KID_SIZE);
	qsc_intutils_le64to8(info + SIAP_SEAL_LABEL_SIZE + SIAP_KID_SIZE, dkey->expiration);
}

static void siap_server_passphrase_verifier_generate(uint8_t* verifier, const uint8_t* phash, const uint8_t* kid)
{
#if defined(SIAP_EXTENDED_ENCRYPTION)
	qsc_cshake512_compute(verifier, SIAP_HASH_SIZE, phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_PASSVERIFY_LABEL, SIAP_PASSVERIFY_LABEL_SIZE, kid, SIAP_KID_SIZE);
#else
	qsc_cshake256_compute(verifier, SIAP_HASH_SIZE, phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_PASSVERIFY_LABEL, SIAP_PASSVERIFY_LABEL_SIZE, kid, SIAP_KID_SIZE);
#endif
}

static bool siap_server_encrypt_device_key_checked(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash)
{
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(phash != NULL);

	uint8_t pkey[SIAP_SERVER_KEY_SIZE + SIAP_NONCE_SIZE] = { 0U };
	uint8_t info[SIAP_SEAL_INFO_SIZE] = { 0U };
	uint8_t pctx[SIAP_SALT_SIZE + SIAP_SEAL_INFO_SIZE] = { 0U };
	uint8_t* enkt;
	bool res;

	res = false;
	enkt = NULL;

	if (dkey != NULL && skey != NULL && phash != NULL)
	{
		enkt = (uint8_t*)qsc_memutils_malloc(SIAP_KTREE_SIZE + SIAP_MAC_SIZE);

		if (enkt != NULL)
		{
			qsc_rcs_keyparams kp;
			qsc_rcs_state rstate = { 0U };

			qsc_memutils_clear(enkt, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);
			siap_server_seal_info(info, dkey);
			qsc_memutils_copy(pctx, skey->dsalt, SIAP_SALT_SIZE);
			qsc_memutils_copy(pctx + SIAP_SALT_SIZE, info, SIAP_SEAL_INFO_SIZE);

			/* key hash is: passphrase-hash + protocol label + server-salt + device-id + counter + expiration */
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_SEAL_LABEL, SIAP_SEAL_LABEL_SIZE, pctx, sizeof(pctx));
#else
			qsc_cshake256_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_SEAL_LABEL, SIAP_SEAL_LABEL_SIZE, pctx, sizeof(pctx));
#endif

			kp.key = pkey;
			kp.keylen = SIAP_SERVER_KEY_SIZE;
			kp.nonce = pkey + SIAP_SERVER_KEY_SIZE;
			kp.info = info;
			kp.infolen = sizeof(info);

			/* initialize the cipher */
			qsc_rcs_initialize(&rstate, &kp, true);
			/* encrypt the token tree */
			res = qsc_rcs_transform(&rstate, enkt, dkey->ktree, SIAP_KTREE_SIZE);

			if (res == true)
			{
				/* copy to device key token-tree */
				qsc_memutils_copy(dkey->ktree, enkt, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);
			}

			/* cleanup */
			qsc_memutils_secure_erase(enkt, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);
			qsc_memutils_alloc_free(enkt);
			enkt = NULL;
			qsc_memutils_secure_erase(pkey, sizeof(pkey));
			qsc_memutils_secure_erase(info, sizeof(info));
			qsc_memutils_secure_erase(pctx, sizeof(pctx));
			qsc_rcs_dispose(&rstate);
		}
	}

	return res;
}

siap_errors siap_server_authenticate_device(uint8_t* dtok, siap_device_key* dkey, siap_device_tag* dtag, const siap_server_key* skey, const uint8_t* phash)
{
	SIAP_ASSERT(dtok != NULL);
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(dtag != NULL);
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(phash != NULL);

	uint8_t stok[SIAP_AUTHENTICATION_TOKEN_SIZE] = { 0U };
	uint8_t vhash[SIAP_HASH_SIZE] = { 0U };
	siap_device_key* bkey;
	siap_errors err;
	bool decrypted;
	bool res;

	err = siap_error_invalid_input;
	decrypted = false;
	bkey = NULL;

	if (dtok != NULL && dkey != NULL && dtag != NULL && skey != NULL && phash != NULL)
	{
		bkey = (siap_device_key*)qsc_memutils_malloc(sizeof(siap_device_key));

		if (bkey != NULL)
		{
			qsc_memutils_copy(bkey, dkey, sizeof(siap_device_key));
			/* start by comparing the device kid with the tag kid */
			res = qsc_memutils_are_equal(dkey->kid, dtag->kid, SIAP_KID_SIZE);

			if (res == true)
			{
				uint64_t tnow;

				tnow = qsc_timestamp_epochtime_seconds();

				/* check for a valid expiration time */
				res = (dkey->expiration <= skey->expiration &&
					dkey->expiration > tnow &&
					dkey->expiration <= (tnow + SIAP_KEY_DURATION_SECONDS));

				if (res == true)
				{
					/* verify the passphrase-derived verifier stored in the device tag */
					siap_server_passphrase_verifier_generate(vhash, phash, dtag->kid);
					res = (qsc_intutils_verify(dtag->phash, vhash, SIAP_HASH_SIZE) == 0U);

					if (res == true)
					{
						/* decrypt the device key using the live passphrase hash, not the stored verifier */
						res = siap_server_decrypt_device_key(dkey, skey, phash);

						if (res == true)
						{
							decrypted = true;
							/* verify the token key tree is unaltered */
							res = siap_server_verify_device_tag(dtag, dkey);

							if (res == true)
							{
								uint32_t kidx;

								/* generate a token at the server and compare before mutating the tree */
								res = siap_server_generate_authentication_token(stok, dtag, skey);

								if (res == true)
								{
									kidx = qsc_intutils_be8to32(dkey->kid + SIAP_DID_SIZE);
									res = (kidx < SIAP_KTREE_COUNT);

									if (res == true)
									{
										res = qsc_memutils_are_equal(dkey->ktree + (((size_t)kidx) * SIAP_AUTHENTICATION_TOKEN_SIZE), stok, SIAP_AUTHENTICATION_TOKEN_SIZE);
									}

									if (res == true)
									{
										/* extract the authentication token from the device key after authentication succeeds */
										res = siap_server_extract_authentication_token(dtok, dkey, skey);

										if (res == true)
										{
											/* update the device tag */
											siap_server_generate_device_tag(dtag, dkey, phash);
											/* encrypt the device key */
											res = siap_server_encrypt_device_key_checked(dkey, skey, phash);

											if (res == true)
											{
												err = siap_error_none;
												decrypted = false;
											}
											else
											{
												err = siap_error_decryption_failure;
											}
										}
										else
										{
											err = siap_error_token_invalid;
										}
									}
									else
									{
										err = siap_error_authentication_failure;
									}
								}
								else
								{
									err = siap_error_token_not_created;
								}
							}
							else
							{
								err = siap_error_token_tree_invalid;
							}
						}
						else
						{
							err = siap_error_decryption_failure;
						}
					}
					else
					{
						err = siap_error_passphrase_unrecognized;
					}
				}
				else
				{
					err = siap_error_key_expired;
				}
			}
			else
			{
				err = siap_error_identity_mismatch;
			}

			if (err != siap_error_none && decrypted == true)
			{
				qsc_memutils_copy(dkey, bkey, sizeof(siap_device_key));
			}

			qsc_memutils_secure_erase(bkey, sizeof(siap_device_key));
			qsc_memutils_alloc_free(bkey);
			bkey = NULL;
		}
	}

	qsc_memutils_secure_erase(stok, SIAP_AUTHENTICATION_TOKEN_SIZE);
	qsc_memutils_secure_erase(vhash, SIAP_HASH_SIZE);

	return err;
}

bool siap_server_generate_authentication_token(uint8_t* token, const siap_device_tag* dtag, const siap_server_key* skey)
{
	SIAP_ASSERT(token != NULL);
	SIAP_ASSERT(dtag != NULL);
	SIAP_ASSERT(skey != NULL);

	uint32_t kidx;
	bool res;

	res = false;

	if (token != NULL && dtag != NULL && skey != NULL)
	{
		/* get the current key index and key pointer */
		kidx = qsc_intutils_be8to32(dtag->kid + SIAP_DID_SIZE);

		if (kidx < SIAP_KTREE_COUNT)
		{
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(token, SIAP_AUTHENTICATION_TOKEN_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, dtag->kid, SIAP_KID_SIZE);
#else
			qsc_cshake256_compute(token, SIAP_AUTHENTICATION_TOKEN_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, dtag->kid, SIAP_KID_SIZE);
#endif
			res = true;
		}
	}

	return res;
}

bool siap_server_decrypt_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash)
{
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(phash != NULL);

	uint8_t pkey[SIAP_SERVER_KEY_SIZE + SIAP_NONCE_SIZE] = { 0U };
	uint8_t info[SIAP_SEAL_INFO_SIZE] = { 0U };
	uint8_t pctx[SIAP_SALT_SIZE + SIAP_SEAL_INFO_SIZE] = { 0U };
	uint8_t* dect;
	bool res;

	res = false;
	dect = NULL;

	if (dkey != NULL && skey != NULL && phash != NULL)
	{
		dect = (uint8_t*)qsc_memutils_malloc(SIAP_KTREE_SIZE);

		if (dect != NULL)
		{
			qsc_rcs_keyparams kp;
			qsc_rcs_state rstate = { 0U };

			qsc_memutils_clear(dect, SIAP_KTREE_SIZE);
			siap_server_seal_info(info, dkey);
			qsc_memutils_copy(pctx, skey->dsalt, SIAP_SALT_SIZE);
			qsc_memutils_copy(pctx + SIAP_SALT_SIZE, info, SIAP_SEAL_INFO_SIZE);

			/* key hash is: passphrase-hash + protocol label + server-salt + device-id + counter + expiration */
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_SEAL_LABEL, SIAP_SEAL_LABEL_SIZE, pctx, sizeof(pctx));
#else
			qsc_cshake256_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, (const uint8_t*)SIAP_SEAL_LABEL, SIAP_SEAL_LABEL_SIZE, pctx, sizeof(pctx));
#endif

			kp.key = pkey;
			kp.keylen = SIAP_SERVER_KEY_SIZE;
			kp.nonce = pkey + SIAP_SERVER_KEY_SIZE;
			kp.info = info;
			kp.infolen = sizeof(info);

			/* initialize the cipher */
			qsc_rcs_initialize(&rstate, &kp, false);

			/* authenticate and conditionally decrypt token-tree */
			res = qsc_rcs_transform(&rstate, dect, dkey->ktree, SIAP_KTREE_SIZE);

			if (res == true)
			{
				/* copy to tree state */
				qsc_memutils_copy(dkey->ktree, dect, SIAP_KTREE_SIZE);
			}

			/* cleanup */
			qsc_memutils_secure_erase(dect, SIAP_KTREE_SIZE);
			qsc_memutils_alloc_free(dect);
			dect = NULL;
			qsc_memutils_secure_erase(pkey, sizeof(pkey));
			qsc_memutils_secure_erase(info, sizeof(info));
			qsc_memutils_secure_erase(pctx, sizeof(pctx));
			qsc_rcs_dispose(&rstate);
		}
	}

	return res;
}

void siap_server_encrypt_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash)
{
	(void)siap_server_encrypt_device_key_checked(dkey, skey, phash);
}

bool siap_server_extract_authentication_token(uint8_t* token, siap_device_key* dkey, const siap_server_key* skey)
{
	SIAP_ASSERT(token != NULL);
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(skey != NULL);

	uint32_t kidx;
	bool res;

	res = false;

	if (token != NULL && dkey != NULL && skey != NULL)
	{
		/* get the current key index and key pointer */
		kidx = qsc_intutils_be8to32(dkey->kid + SIAP_DID_SIZE);

		if (kidx < SIAP_KTREE_COUNT)
		{
			/* copy the token and clear it from the tree */
			qsc_memutils_copy(token, dkey->ktree + (((size_t)kidx) * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE);
			qsc_memutils_secure_erase(dkey->ktree + (((size_t)kidx) * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE);
			/* increment the kid counter */
			qsc_intutils_be8increment(dkey->kid + SIAP_DID_SIZE, SIAP_KEY_ID_SIZE);
			res = true;
		}
	}

	return res;
}

void siap_server_generate_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* did)
{
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(did != NULL);

	if (dkey != NULL && skey != NULL && did != NULL)
	{
		/* copy the did */
		qsc_memutils_copy(dkey->kid, did, SIAP_DID_SIZE);

		/* set the expiration time */
		dkey->expiration = skey->expiration;

		/* generate the token set; the incrementing kid/kidx in custom param creates a keccak counter-mode generator */
		for (size_t i = 0U; i < SIAP_KTREE_COUNT; ++i)
		{
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(dkey->ktree + (i * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, dkey->kid, SIAP_KID_SIZE);
#else
			qsc_cshake256_compute(dkey->ktree + (i * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, dkey->kid, SIAP_KID_SIZE);
#endif
			qsc_intutils_be8increment(dkey->kid + SIAP_DID_SIZE, SIAP_KEY_ID_SIZE);
		}

		/* reset the counter */
		qsc_memutils_clear(dkey->kid + SIAP_DID_SIZE, SIAP_KEY_ID_SIZE);
	}
}

void siap_server_generate_device_tag(siap_device_tag* dtag, const siap_device_key* dkey, const uint8_t* phash)
{
	SIAP_ASSERT(dtag != NULL);
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(phash != NULL);

	if (dtag != NULL && dkey != NULL && phash != NULL)
	{
		/* copy the kid */
		qsc_memutils_copy(dtag->kid, dkey->kid, SIAP_KID_SIZE);
		/* store a passphrase verifier, not the sealing-key precursor */
		siap_server_passphrase_verifier_generate(dtag->phash, phash, dkey->kid);

		/* hash the entire key tree and add it to khash */
#if defined(SIAP_EXTENDED_ENCRYPTION)
		qsc_shake512_compute(dtag->khash, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#else
		qsc_shake256_compute(dtag->khash, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#endif
	}
}

bool siap_server_generate_server_key(siap_server_key* skey, const uint8_t* sid)
{
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(sid != NULL);

	bool res;

	res = false;

	if (skey != NULL && sid != NULL)
	{
		/* generate the base key */
		res = qsc_acp_generate(skey->kbase, SIAP_SERVER_KEY_SIZE);

		if (res == true)
		{
			/* copy the sid */
			qsc_memutils_copy(skey->sid, sid, SIAP_SID_SIZE);

			/* set the expiration time */
			skey->expiration = qsc_timestamp_epochtime_seconds() + SIAP_KEY_DURATION_SECONDS;

			/* generate the salt */
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(skey->dsalt, SIAP_SALT_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, skey->sid, SIAP_SID_SIZE);
#else
			qsc_cshake256_compute(skey->dsalt, SIAP_SALT_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, skey->sid, SIAP_SID_SIZE);
#endif
		}
	}

	return res;
}

void siap_server_passphrase_generate(char* passphrase, size_t length)
{
	SIAP_ASSERT(passphrase != NULL);

	char trnd[128U] = { 0U };
	size_t clen;

	if (passphrase != NULL && length != 0U)
	{
		clen = 0U;
		qsc_memutils_clear(passphrase, length);

		while (clen < (length - 1U))
		{
			if (qsc_acp_generate((uint8_t*)trnd, sizeof(trnd)) == false)
			{
				break;
			}

			for (size_t i = 0U; i < sizeof(trnd); ++i)
			{
				if (trnd[i] > 32 && trnd[i] < 127)
				{
					passphrase[clen] = trnd[i];
					++clen;

					if (clen >= (length - 1U))
					{
						break;
					}
				}
			}

			qsc_memutils_secure_erase(trnd, sizeof(trnd));
		}
	}
}

void siap_server_passphrase_hash_generate(uint8_t* phash, const char* passphrase, size_t passlen)
{
	SIAP_ASSERT(phash != NULL);
	SIAP_ASSERT(passphrase != NULL);

	qsc_scb_state sscb = { 0U };
	uint8_t seed[SIAP_HASH_SIZE] = { 0U };

	if (phash != NULL && passphrase != NULL)
	{
		qsc_memutils_clear(phash, SIAP_HASH_SIZE);

		if (passlen != 0U && passlen <= SIAP_CLIENT_PASSWORD_MAX)
		{
#if defined(SIAP_EXTENDED_ENCRYPTION)
			qsc_cshake512_compute(seed, sizeof(seed), (const uint8_t*)passphrase, passlen, (const uint8_t*)SIAP_PASSHASH_LABEL, SIAP_PASSHASH_LABEL_SIZE, (const uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE);
#else
			qsc_cshake256_compute(seed, sizeof(seed), (const uint8_t*)passphrase, passlen, (const uint8_t*)SIAP_PASSHASH_LABEL, SIAP_PASSHASH_LABEL_SIZE, (const uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE);
#endif
			qsc_scb_initialize(&sscb, seed, sizeof(seed), (const uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, SIAP_SCB_CPU_COST, SIAP_SCB_MEMORY_COST);

			if (qsc_scb_generate(&sscb, phash, SIAP_HASH_SIZE) == false)
			{
				qsc_memutils_clear(phash, SIAP_HASH_SIZE);
			}

			qsc_scb_dispose(&sscb);
		}
	}

	qsc_memutils_secure_erase(seed, sizeof(seed));
}

bool siap_server_passphrase_hash_verify(const uint8_t* phash, const char* passphrase, size_t passlen)
{
	SIAP_ASSERT(phash != NULL);
	SIAP_ASSERT(passphrase != NULL);

	uint8_t tmph[SIAP_HASH_SIZE] = { 0U };
	bool res;

	res = false;

	if (phash != NULL && passphrase != NULL)
	{
		siap_server_passphrase_hash_generate(tmph, passphrase, passlen);
		res = (qsc_intutils_verify(tmph, phash, SIAP_HASH_SIZE) == 0U);
	}

	qsc_memutils_secure_erase(tmph, sizeof(tmph));

	return res;
}

bool siap_server_verify_device_tag(siap_device_tag* dtag, const siap_device_key* dkey)
{
	SIAP_ASSERT(dtag != NULL);
	SIAP_ASSERT(dkey != NULL);

	uint8_t tmph[SIAP_KTAG_STATE_HASH] = { 0U };
	bool res;

	res = false;

	if (dtag != NULL && dkey != NULL)
	{
		/* hash the entire key tree and compare it with khash */
#if defined(SIAP_EXTENDED_ENCRYPTION)
		qsc_shake512_compute(tmph, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#else
		qsc_shake256_compute(tmph, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#endif

		res = (qsc_intutils_verify(tmph, dtag->khash, SIAP_KTAG_STATE_HASH) == 0U);
	}

	qsc_memutils_secure_erase(tmph, sizeof(tmph));

	return res;
}
