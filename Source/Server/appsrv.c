#include "appsrv.h"
#include "logger.h"
#include "siap.h"
#include "server.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"

static void server_print_line(const char* message)
{
	if (message != NULL)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void server_print_passphrase(char* pass)
{
	qsc_consoleutils_print_safe("server> ");
	qsc_consoleutils_print_safe("The user passphrase has been generated: ");
	qsc_consoleutils_print_line(pass);
}

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			qsc_consoleutils_print_safe("server> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_safe("server> ");
		}
	}
}

static void server_print_string(const char* message)
{
	if (message != NULL)
	{
		qsc_consoleutils_print_safe("server> ");
		qsc_consoleutils_print_safe(message);
	}
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("***********************************************************");
	qsc_consoleutils_print_line("* SIAP: Symmetric Infrastructure Access Protocol          *");
	qsc_consoleutils_print_line("*                                                         *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0b (A1)                               *");
	qsc_consoleutils_print_line("* Date:      May 28, 2026                                 *");
	qsc_consoleutils_print_line("* Contact:   contact@qrcscorp.ca                          *");
	qsc_consoleutils_print_line("***********************************************************");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_app_data, fpath);
#else
	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
#endif
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, SIAP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool server_get_path(char* fpath, size_t pathlen, const char* name)
{
	bool res;

	qsc_stringutils_clear_string(fpath);
	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, name);
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool server_key_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), SIAP_SERVER_KEY_NAME);
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void server_start_logger(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };

	server_get_storage_path(fpath, sizeof(fpath));
	siap_logger_initialize(fpath);
}

static void server_stop_logger(void)
{
	siap_logger_dispose();
}

static bool server_get_console_line(char* line, size_t linelen, size_t* outlen)
{
	bool res;

	res = false;

	if (line != NULL && outlen != NULL && linelen != 0U)
	{
		*outlen = qsc_consoleutils_get_line(line, linelen);

		if (*outlen != 0U)
		{
			--(*outlen);
			res = true;
		}
	}

	return res;
}

static bool server_authenticate_existing_key(void)
{
	siap_device_key dkey = { 0 };
	siap_device_tag dtag = { 0 };
	siap_server_key skey = { 0U };
	char upass[SIAP_SERVER_PASSWORD_MAX] = { 0 };
	uint8_t dskey[SIAP_DEVICE_KEY_ENCODED_SIZE] = { 0U };
	uint8_t dstag[SIAP_DEVICE_TAG_ENCODED_SIZE] = { 0U };
	uint8_t dtok[SIAP_AUTHENTICATION_TOKEN_SIZE] = { 0U };
	uint8_t phash[SIAP_HASH_SIZE] = { 0U };
	uint8_t sskey[SIAP_SERVER_KEY_ENCODED_SIZE] = { 0U };
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t len;
	siap_errors err;
	bool res;

	res = false;
	err = siap_error_invalid_input;

	server_get_path(fpath, sizeof(fpath), SIAP_SERVER_KEY_NAME);
	res = qsc_fileutils_copy_file_to_stream(fpath, (char*)sskey, sizeof(sskey));

	if (res == true)
	{
		res = siap_deserialize_server_key(&skey, sskey, sizeof(sskey));
	}

	if (res == true)
	{
		server_print_message("The server-key has been loaded.");
		server_print_message("Enter the full path to the device key to begin authentication:");
		server_print_prompt();
		len = qsc_consoleutils_get_line(dpath, sizeof(dpath));

		res = (len > sizeof(SIAP_DEVICE_KEY_NAME) &&
			qsc_fileutils_exists(dpath) == true &&
			qsc_stringutils_string_contains(dpath, SIAP_DEVICE_KEY_NAME) == true);
	}

	if (res == true)
	{
		res = qsc_fileutils_copy_file_to_stream(dpath, (char*)dskey, sizeof(dskey));
	}

	if (res == true)
	{
		res = siap_deserialize_device_key(&dkey, dskey, sizeof(dskey));
	}

	if (res == true)
	{
		server_print_message("Enter the passphrase associated with this device key:");
		server_print_prompt();
		res = server_get_console_line(upass, sizeof(upass), &len);
	}

	if (res == true)
	{
		res = (len != 0U && len < sizeof(upass));
	}

	if (res == true)
	{
		siap_server_passphrase_hash_generate(phash, upass, len);
		server_get_path(fpath, sizeof(fpath), SIAP_USER_DATABASE_NAME);
		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)dstag, sizeof(dstag));
	}

	if (res == true)
	{
		res = siap_deserialize_device_tag(&dtag, dstag, sizeof(dstag));
	}

	if (res == true)
	{
		server_print_message("The device-key has been loaded.");
		err = siap_server_authenticate_device(dtok, &dkey, &dtag, &skey, phash);
		siap_log_system_error(err);

		if (err == siap_error_none)
		{
			res = siap_serialize_device_tag(dstag, sizeof(dstag), &dtag);

			if (res == true)
			{
				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)dstag, sizeof(dstag));
			}

			if (res == true)
			{
				res = siap_serialize_device_key(dskey, sizeof(dskey), &dkey);
			}

			if (res == true)
			{
				res = qsc_fileutils_copy_stream_to_file(dpath, (char*)dskey, sizeof(dskey));
			}
		}
		else
		{
			res = false;
		}
	}
	else
	{
		siap_log_system_error(err);
	}

	qsc_memutils_secure_erase(&dkey, sizeof(dkey));
	qsc_memutils_secure_erase(&dtag, sizeof(dtag));
	qsc_memutils_secure_erase(&skey, sizeof(skey));
	qsc_memutils_secure_erase(upass, sizeof(upass));
	qsc_memutils_secure_erase(dskey, sizeof(dskey));
	qsc_memutils_secure_erase(dstag, sizeof(dstag));
	qsc_memutils_secure_erase(dtok, sizeof(dtok));
	qsc_memutils_secure_erase(phash, sizeof(phash));
	qsc_memutils_secure_erase(sskey, sizeof(sskey));

	return res;
}

static bool server_generate_new_keyset(void)
{
	siap_device_key dkey = { 0 };
	siap_device_tag dtag = { 0 };
	siap_server_key skey = { 0U };
	char upass[SIAP_SERVER_PASSWORD_MAX] = { 0 };
	uint8_t dskey[SIAP_DEVICE_KEY_ENCODED_SIZE] = { 0U };
	uint8_t dstag[SIAP_DEVICE_TAG_ENCODED_SIZE] = { 0U };
	uint8_t keyid[SIAP_KID_SIZE] = { 0U };
	uint8_t phash[SIAP_HASH_SIZE] = { 0U };
	uint8_t sskey[SIAP_SERVER_KEY_ENCODED_SIZE] = { 0U };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char strid[(SIAP_DID_SIZE * 2U) + 2U] = { 0 };
	size_t ctr;
	size_t len;
	bool res;

	server_print_message("The server-key was not detected, generating new server/device keys.");
	ctr = 0U;
	res = false;

	while (ctr < 3U)
	{
		++ctr;
		server_print_message("Enter a 32 character hexidecimal server/device key identity, ex. 000102030405060708090A0B0C0D0E0F");
		server_print_prompt();
		res = server_get_console_line(strid, sizeof(strid), &len);

		if (res == true && len == (2U * SIAP_DID_SIZE) && qsc_stringutils_is_hex(strid, len) == true)
		{
			qsc_intutils_hex_to_bin(strid, keyid, SIAP_DID_SIZE);
			res = true;
			break;
		}

		res = false;
	}

	if (res == true)
	{
		res = siap_server_generate_server_key(&skey, keyid);
	}

	if (res == true)
	{
		siap_server_generate_device_key(&dkey, &skey, keyid);
		server_get_path(fpath, sizeof(fpath), SIAP_SERVER_KEY_NAME);
		res = siap_serialize_server_key(sskey, sizeof(sskey), &skey);
	}

	if (res == true)
	{
		res = qsc_fileutils_copy_stream_to_file(fpath, (char*)sskey, sizeof(sskey));
	}

	if (res == true)
	{
		server_print_string("The server-key has been saved to ");
		server_print_line(fpath);
		siap_server_passphrase_generate(upass, SIAP_HASH_SIZE + 1U);
		server_print_passphrase(upass);
		siap_server_passphrase_hash_generate(phash, upass, qsc_stringutils_string_size(upass));
		siap_server_generate_device_tag(&dtag, &dkey, phash);
		res = siap_serialize_device_tag(dstag, sizeof(dstag), &dtag);
	}

	if (res == true)
	{
		server_get_path(fpath, sizeof(fpath), SIAP_USER_DATABASE_NAME);
		res = qsc_fileutils_copy_stream_to_file(fpath, (char*)dstag, sizeof(dstag));
	}

	if (res == true)
	{
		server_print_string("The database has been saved to ");
		server_print_line(fpath);
		siap_server_encrypt_device_key(&dkey, &skey, phash);
		server_get_path(fpath, sizeof(fpath), SIAP_DEVICE_KEY_NAME);
		res = siap_serialize_device_key(dskey, sizeof(dskey), &dkey);
	}

	if (res == true)
	{
		res = qsc_fileutils_copy_stream_to_file(fpath, (char*)dskey, sizeof(dskey));
	}

	if (res == true)
	{
		server_print_string("The device-key has been saved to ");
		server_print_line(fpath);
		server_print_message("Distribute the device-key to the intended client.");
	}
	else
	{
		siap_log_system_error(siap_error_file_copy_failure);
	}

	qsc_memutils_secure_erase(&dkey, sizeof(dkey));
	qsc_memutils_secure_erase(&dtag, sizeof(dtag));
	qsc_memutils_secure_erase(&skey, sizeof(skey));
	qsc_memutils_secure_erase(upass, sizeof(upass));
	qsc_memutils_secure_erase(dskey, sizeof(dskey));
	qsc_memutils_secure_erase(dstag, sizeof(dstag));
	qsc_memutils_secure_erase(keyid, sizeof(keyid));
	qsc_memutils_secure_erase(phash, sizeof(phash));
	qsc_memutils_secure_erase(sskey, sizeof(sskey));

	return res;
}

static bool server_key_dialogue(void)
{
	bool res;

	server_start_logger();

	if (server_key_exists() == true)
	{
		res = server_authenticate_existing_key();
	}
	else
	{
		res = server_generate_new_keyset();
	}

	return res;
}

int main(void)
{
	bool keyex;
	bool res;

	server_print_banner();
	keyex = server_key_exists();
	res = server_key_dialogue();

	if (res == true)
	{
		if (keyex == true)
		{
			server_print_message("Success! The device has been authenticated.");
		}
		else
		{
			server_print_message("Success! The server and device keys have been created, restart to test.");
		}
	}
	else
	{
		if (keyex == true)
		{
			server_print_message("Failure! The device authentication has failed.");
		}
		else
		{
			server_print_message("Failure! The server and device keys could not be created.");
		}
	}

	server_stop_logger();
	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
