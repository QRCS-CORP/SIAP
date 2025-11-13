#include "siap.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "timestamp.h"

void siap_deserialize_device_key(siap_device_key* dkey, const uint8_t* input)
{
	SIAP_ASSERT(dkey != NULL);
	SIAP_ASSERT(input != NULL);

	size_t pos;

	if (dkey != NULL && input != NULL)
	{
		qsc_memutils_copy(dkey->ktree, input, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);
		pos = SIAP_KTREE_SIZE + SIAP_MAC_SIZE;
		qsc_memutils_copy(dkey->kid, input + pos, SIAP_KID_SIZE);
		pos += SIAP_KID_SIZE;
		dkey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void siap_serialize_device_key(uint8_t* output, const siap_device_key* dkey)
{
	SIAP_ASSERT(output != NULL);
	SIAP_ASSERT(dkey != NULL);

	size_t pos;

	if (output != NULL && dkey != NULL)
	{
		qsc_memutils_copy(output, dkey->ktree, SIAP_KTREE_SIZE + SIAP_MAC_SIZE);
		pos = SIAP_KTREE_SIZE + SIAP_MAC_SIZE;
		qsc_memutils_copy(output + pos, dkey->kid, SIAP_KID_SIZE);
		pos += SIAP_KID_SIZE;
		qsc_intutils_le64to8(output + pos, dkey->expiration);
	}
}

void siap_deserialize_device_tag(siap_device_tag* dtag, const uint8_t* input)
{
	SIAP_ASSERT(dtag != NULL);
	SIAP_ASSERT(input != NULL);

	size_t pos;

	if (dtag != NULL && input != NULL)
	{
		qsc_memutils_copy(dtag->kid, input, SIAP_KID_SIZE);
		pos = SIAP_KID_SIZE;
		qsc_memutils_copy(dtag->khash, input + pos, SIAP_KTAG_STATE_HASH);
		pos += SIAP_KTAG_STATE_HASH;
		qsc_memutils_copy(dtag->phash, input + pos, SIAP_HASH_SIZE);
	}
}

void siap_serialize_device_tag(uint8_t* output, const siap_device_tag* dtag)
{
	SIAP_ASSERT(output != NULL);
	SIAP_ASSERT(dtag != NULL);

	size_t pos;

	if (output != NULL && dtag != NULL)
	{
		qsc_memutils_copy(output, dtag->kid, SIAP_KID_SIZE);
		pos = SIAP_KID_SIZE;
		qsc_memutils_copy(output + pos, dtag->khash, SIAP_KTAG_STATE_HASH);
		pos += SIAP_KTAG_STATE_HASH;
		qsc_memutils_copy(output + pos, dtag->phash, SIAP_HASH_SIZE);
	}
}

void siap_deserialize_server_key(siap_server_key* skey, const uint8_t* input)
{
	SIAP_ASSERT(skey != NULL);
	SIAP_ASSERT(input != NULL);

	size_t pos;

	if (skey != NULL && input != NULL)
	{
		qsc_memutils_copy(skey->kbase, input, SIAP_SERVER_KEY_SIZE);
		pos = SIAP_SERVER_KEY_SIZE;
		qsc_memutils_copy(skey->sid, input + pos, SIAP_SID_SIZE);
		pos += SIAP_SID_SIZE;
		qsc_memutils_copy(skey->dsalt, input + pos, SIAP_SALT_SIZE);
		pos += SIAP_SALT_SIZE;
		skey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void siap_serialize_server_key(uint8_t* output, const siap_server_key* skey)
{
	SIAP_ASSERT(output != NULL);
	SIAP_ASSERT(skey != NULL);

	size_t pos;

	if (output != NULL && skey != NULL)
	{
		qsc_memutils_copy(output, skey->kbase, SIAP_SERVER_KEY_SIZE);
		pos = SIAP_SERVER_KEY_SIZE;
		qsc_memutils_copy(output + pos, skey->sid, SIAP_SID_SIZE);
		pos += SIAP_SID_SIZE;
		qsc_memutils_copy(output + pos, skey->dsalt, SIAP_SALT_SIZE);
		pos += SIAP_SALT_SIZE;
		qsc_intutils_le64to8(output + pos, skey->expiration);
	}
}

void siap_increment_device_key(siap_device_key* dkey)
{
	uint32_t ctr;

	/* get the key id */
	ctr = qsc_intutils_be8to32(dkey->kid + SIAP_DID_SIZE);
	/* clear the key at the current position */
	qsc_memutils_clear(dkey->ktree + (ctr * SIAP_AUTHENTICATION_TOKEN_SIZE), SIAP_AUTHENTICATION_TOKEN_SIZE);
	/* increment and write the new key index to the kid */
	++ctr;
	qsc_intutils_be32to8(dkey->kid + SIAP_DID_SIZE, ctr);
}

const char* siap_get_error_description(siap_errors message)
{
	const char* dsc;

	dsc = NULL;

	if (message < SIAP_ERROR_STRING_DEPTH && message >= 0)
	{
		dsc = SIAP_ERROR_STRINGS[(size_t)message];

	}

	return dsc;
}

void siap_log_system_error(siap_errors err)
{
	const char* pmsg;

	pmsg = siap_error_to_string(err);
	
	if (pmsg != NULL)
	{
		siap_logger_write(pmsg);
	}
}

void siap_log_error(siap_errors emsg, const char* msg)
{
	SIAP_ASSERT(msg != NULL);

	char mtmp[SIAP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* pmsg;

	pmsg = siap_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			siap_logger_write(mtmp);
		}
		else
		{
			siap_logger_write(pmsg);
		}
	}
}

const char* siap_error_to_string(siap_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < SIAP_ERROR_STRING_DEPTH)
	{
		dsc = SIAP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}
