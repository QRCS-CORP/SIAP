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

siap_errors siap_server_authenticate_device(uint8_t* dtok, siap_device_key* dkey, siap_device_tag* dtag, const siap_server_key* skey, const uint8_t* phash)
{
	uint8_t stok[SIAP_AUTHENTICATION_TOKEN_SIZE] = { 0U };
	siap_errors err;
	bool res;

	err = siap_error_none;

	/* start by comparing the device kid with the tag kid */
	res = qsc_memutils_are_equal(dkey->kid, dtag->kid, SIAP_KID_SIZE);

	if (res == true)
	{
		/* check for a valid expiration time */
		res = (dkey->expiration <= skey->expiration && dkey->expiration <= (qsc_timestamp_epochtime_seconds() + SIAP_KEY_DURATION_SECONDS));

		if (res == true)
		{
			/* verify the passphrase hash */
			res = (qsc_intutils_verify(dtag->phash, phash, SIAP_HASH_SIZE) == 0U);

			if (res == true)
			{
				/* decrypt the device key */
				res = siap_server_decrypt_device_key(dkey, skey, dtag->phash);

				if (res == true)
				{
					/* verify the token key tree is unaltered */
					res = siap_server_verify_device_tag(dtag, dkey);

					if (res == true)
					{
						/* extract the authentication token from the device key */
						res = siap_server_extract_authentication_token(dtok, dkey, skey);

						if (res == true)
						{
							/* generate a token at the server and compare */
							res = siap_server_generate_authentication_token(stok, dtag, skey);

							if (res == true)
							{
								res = qsc_memutils_are_equal(dtok, stok, SIAP_AUTHENTICATION_TOKEN_SIZE);

								/* cleanup */
								qsc_memutils_clear(stok, SIAP_AUTHENTICATION_TOKEN_SIZE);

								if (res == true)
								{
									/* important! make sure to re-save both of these structures to file */

									/* update the device tag */
									siap_server_generate_device_tag(dtag, dkey, phash);
									/* encrypt the device key */
									siap_server_encrypt_device_key(dkey, skey, phash);
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
							err = siap_error_token_invalid;
						}
					}
					else
					{
						err = siap_error_decryption_failure;
					}
				}
				else
				{
					err = siap_error_token_tree_invalid;
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

	uint8_t dect[SIAP_KTREE_SIZE] = { 0U };
	uint8_t pkey[SIAP_SERVER_KEY_SIZE + SIAP_NONCE_SIZE] = { 0U };
	bool res;

	res = false;

	if (dkey != NULL && skey != NULL && phash != NULL)
	{
		/* using kid as the name param with the incrementing kidx ensures key/nonce uniqueness every encryption cycle */
		/* key hash is: passphrase-hash + device-id + counter + server-salt: k = H(ph, did/kidx++, s) */
#if defined(SIAP_EXTENDED_ENCRYPTION)
		qsc_cshake512_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, dkey->kid, SIAP_KID_SIZE, skey->dsalt, SIAP_SALT_SIZE);
#else
		qsc_cshake256_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, dkey->kid, SIAP_KID_SIZE, skey->dsalt, SIAP_SALT_SIZE);
#endif

		qsc_rcs_keyparams kp = { .info = NULL, .infolen = 0U, .key = pkey, .keylen = SIAP_SERVER_KEY_SIZE, .nonce = pkey + SIAP_SERVER_KEY_SIZE };
		qsc_rcs_state rstate = { 0U };

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
		qsc_memutils_clear(dect, sizeof(dect));
		qsc_memutils_clear(pkey, sizeof(pkey));
		qsc_rcs_dispose(&rstate);
	}

	return res;
}

void siap_server_encrypt_device_key(siap_device_key* dkey, const siap_server_key* skey, const uint8_t* phash)
{
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(phash != NULL);

	uint8_t enkt[SIAP_KTREE_SIZE + SIAP_MAC_SIZE] = { 0U };
	uint8_t pkey[SIAP_SERVER_KEY_SIZE + SIAP_NONCE_SIZE] = { 0U };

	if (dkey != NULL && skey != NULL && phash != NULL)
	{
		/* key hash is: passphrase-hash + device-id + counter + server-salt: k = H(ph, did/kidx++, s) */
#if defined(SIAP_EXTENDED_ENCRYPTION)
		qsc_cshake512_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, dkey->kid, SIAP_KID_SIZE, skey->dsalt, SIAP_SALT_SIZE);
#else
		qsc_cshake256_compute(pkey, sizeof(pkey), phash, SIAP_HASH_SIZE, dkey->kid, SIAP_KID_SIZE, skey->dsalt, SIAP_SALT_SIZE);
#endif

		qsc_rcs_keyparams kp = { .info = NULL, .infolen = 0U, .key = pkey, .keylen = SIAP_SERVER_KEY_SIZE, .nonce = pkey + SIAP_SERVER_KEY_SIZE };
		qsc_rcs_state rstate = { 0U };

		/* initialize the cipher */
		qsc_rcs_initialize(&rstate, &kp, true);
		/* encrypt the token tree */
		qsc_rcs_transform(&rstate, enkt, dkey->ktree, SIAP_KTREE_SIZE);
		/* copy to device key token-tree */
		qsc_memutils_copy(dkey->ktree, enkt, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);

		/* cleanup */
		qsc_memutils_clear(enkt, sizeof(enkt));
		qsc_memutils_clear(pkey, sizeof(pkey));
		qsc_rcs_dispose(&rstate);
	}
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
			qsc_memutils_copy(token, dkey->ktree + (kidx * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE);
			qsc_memutils_clear(dkey->ktree + (kidx * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE);
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
		/* copy the passphrase hash*/
		qsc_memutils_copy(dtag->phash, phash, SIAP_HASH_SIZE);

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
			qsc_cshake512_compute(skey->dsalt, SIAP_SALT_SIZE, skey->kbase, SIAP_SERVER_KEY_SIZE, (uint8_t*)SIAP_CONFIG_STRING, SIAP_CONFIG_SIZE, sid, SIAP_SID_SIZE);
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

	if (passphrase != NULL)
	{
		clen = 0U;

		while (clen < length)
		{
			qsc_acp_generate((uint8_t*)trnd, sizeof(trnd));

			for (size_t i = 0U; i < sizeof(trnd); ++i)
			{
				if (trnd[i] > 32 && trnd[i] < 127)
				{
					passphrase[clen] = trnd[i];
					++clen;

					if (clen >= length - 1U)
					{
						break;
					}
				}
			}

			qsc_memutils_clear(trnd, sizeof(trnd));
		}
	}
}

void siap_server_passphrase_hash_generate(uint8_t* phash, const char* passphrase, size_t passlen)
{
	SIAP_ASSERT(phash != NULL);
	SIAP_ASSERT(passphrase != NULL);

	qsc_scb_state sscb = { 0U };

	if (phash != NULL && passphrase != NULL)
	{
		qsc_scb_initialize(&sscb, (uint8_t*)passphrase, passlen, NULL, 0U, 1U, 1U);
		qsc_scb_generate(&sscb, phash, SIAP_HASH_SIZE);
		qsc_scb_dispose(&sscb);
	}
}

bool siap_server_passphrase_hash_verify(const uint8_t* phash, const char* passphrase, size_t passlen)
{
	SIAP_ASSERT(phash != NULL);
	SIAP_ASSERT(passphrase != NULL);

	uint8_t tmph[SIAP_HASH_SIZE] = { 0U };

	if (phash != NULL && passphrase != NULL)
	{
		siap_server_passphrase_hash_generate(tmph, passphrase, passlen);
	}

	return (qsc_intutils_verify(tmph, phash, SIAP_HASH_SIZE) == 0U);
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
		/* hash the entire key tree and add it to khash */
#if defined(SIAP_EXTENDED_ENCRYPTION)
		qsc_shake512_compute(tmph, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#else
		qsc_shake256_compute(tmph, SIAP_KTAG_STATE_HASH, dkey->ktree, SIAP_KTREE_SIZE);
#endif

		res = (qsc_intutils_verify(tmph, dtag->khash, SIAP_KTAG_STATE_HASH) == 0U);
	}

	return res;
}
