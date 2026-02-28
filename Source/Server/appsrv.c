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

		if (slen != 0)
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
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A1)                               *");
	qsc_consoleutils_print_line("* Date:      November 11, 2025                            *");
	qsc_consoleutils_print_line("* Contact:   contact@qrcscorp.ca                          *");
	qsc_consoleutils_print_line("***********************************************************");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, SIAP_APP_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
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

static bool server_key_dialogue(void)
{
	siap_device_key dkey = { 0 };
	siap_device_tag dtag = { 0 };
	siap_server_key skey = { 0U };
	char upass[SIAP_HASH_SIZE + 2U] = { 0 };
	uint8_t dskey[SIAP_DEVICE_KEY_ENCODED_SIZE] = { 0U };
	uint8_t dstag[SIAP_DEVICE_TAG_ENCODED_SIZE] = { 0U };
	uint8_t phash[SIAP_HASH_SIZE] = { 0U };
	uint8_t sskey[SIAP_SERVER_KEY_ENCODED_SIZE] = { 0U };
	char dpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t ctr;
	size_t len;
	siap_errors err;
	bool res;

	res = false;

	/* start the logging service */
	server_start_logger();

	if (server_key_exists() == true)
	{
		uint8_t dtok[SIAP_AUTHENTICATION_TOKEN_SIZE] = { 0U };

		server_get_path(fpath, sizeof(fpath), SIAP_SERVER_KEY_NAME);
		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)sskey, sizeof(sskey));

		if (res == true)
		{
			siap_deserialize_server_key(&skey, sskey);
			server_print_message("The server-key has been loaded.");

			/* get the device key */
			qsc_memutils_clear(fpath, sizeof(fpath));
			server_print_message("Enter the full path to the device key to begin authentication:");
			server_print_prompt();
			len = qsc_consoleutils_get_line(dpath, sizeof(dpath));

			if (len > sizeof(SIAP_DEVICE_KEY_NAME) && 
				qsc_fileutils_exists(dpath) && 
				qsc_stringutils_string_contains(dpath, SIAP_DEVICE_KEY_NAME) == true)
			{
				res = qsc_fileutils_copy_file_to_stream(dpath, (char*)dskey, sizeof(dskey));

				if (res == true)
				{
					/* deserialize the device key */
					siap_deserialize_device_key(&dkey, dskey);

					/* get the passphrase */
					server_print_message("Enter the passphrase associated with this device key:");
					server_print_prompt();
					len = qsc_consoleutils_get_line(upass, sizeof(upass)) - 1;

					res = (len == SIAP_HASH_SIZE);

					if (res == true)
					{
						/* hash the passphrase with SCB */
						siap_server_passphrase_hash_generate(phash, upass, len);

						/* get the device tag */
						server_get_path(fpath, sizeof(fpath), SIAP_USER_DATABASE_NAME);
						res = qsc_fileutils_copy_file_to_stream(fpath, (char*)dstag, sizeof(dstag));

						if (res == true)
						{
							/* deserialize the tag */
							siap_deserialize_device_tag(&dtag, dstag);
							server_print_message("The device-key has been loaded.");

							/* authenticate the key; the output token can be used as a symmetric key */
							err = siap_server_authenticate_device(dtok, &dkey, &dtag, &skey, phash);

							/* log a failure */
							if (err != siap_error_none)
							{
								siap_log_system_error(err);
								res = false;
							}

							/* log the outcome */
							siap_log_system_error(err);

							/* Important! authenticate updates the structures, so re-save the key and database entry */

							/* re-save the device tag */
							siap_serialize_device_tag(dstag, &dtag);
							qsc_fileutils_copy_stream_to_file(fpath, (char*)dstag, sizeof(dstag));

							/* re-save the device key */
							siap_serialize_device_key(dskey, &dkey);
							qsc_fileutils_copy_stream_to_file(dpath, (char*)dskey, sizeof(dskey));
						}
						else
						{
							siap_log_system_error(siap_error_file_copy_failure);
						}
					}
					else
					{
						siap_log_system_error(siap_error_passphrase_unrecognized);
					}
				}
				else
				{
					siap_log_system_error(siap_error_file_copy_failure);
				}
			}
			else
			{
				res = false;
				siap_log_system_error(siap_error_file_invalid_path);
			}

			/* cleanup */
			qsc_memutils_secure_erase(&dkey, sizeof(dkey));
			qsc_memutils_secure_erase(&dtag, sizeof(dtag));
			qsc_memutils_secure_erase(&skey, sizeof(skey));
			qsc_memutils_secure_erase(upass, sizeof(upass));
			qsc_memutils_secure_erase(&dskey, sizeof(dskey));
			qsc_memutils_secure_erase(dstag, sizeof(dstag));
			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(sskey, sizeof(sskey));
		}
		else
		{
			siap_log_system_error(siap_error_file_read_failure);
			server_print_message("Could not load the server-key, aborting startup.");
		}

		/* cleanup */
		qsc_memutils_clear(dtok, SIAP_AUTHENTICATION_TOKEN_SIZE);
	}
	else
	{
		uint8_t keyid[SIAP_KID_SIZE] = { 0U };
		char strid[(SIAP_DID_SIZE * 2) + 2U] = { 0 };

		server_print_message("The server-key was not detected, generating new server/device keys.");

		ctr = 0U;
		res = false;

		while (ctr < 3U)
		{
			++ctr;
			server_print_message("Enter a 32 character hexidecimal server/device key identity, ex. 000102030405060708090A0B0C0D0E0F");
			server_print_prompt();
			len = qsc_consoleutils_get_line(strid, sizeof(strid)) - 1U;

			if (len == (2U * SIAP_DID_SIZE) && qsc_stringutils_is_hex(strid, len))
			{
				/* set the keys master and server id strings */
				qsc_intutils_hex_to_bin(strid, keyid, SIAP_DID_SIZE);
				res = true;
				break;
			}
		}

		if (res == true)
		{
			/* generate server and device keys */
			siap_server_generate_server_key(&skey, keyid);
			siap_server_generate_device_key(&dkey, &skey, keyid);

			/* store the server key */
			server_get_path(fpath, sizeof(fpath), SIAP_SERVER_KEY_NAME);
			siap_serialize_server_key(sskey, &skey);
			res = qsc_fileutils_copy_stream_to_file(fpath, (char*)sskey, sizeof(sskey));

			if (res == true)
			{
				server_print_string("server> The server-key has been saved to ");
				server_print_line(fpath);

				/* create and print the passphrase */
				siap_server_passphrase_generate(upass, SIAP_HASH_SIZE);
				server_print_passphrase(upass);

				/* create and store the database entry */

				/* hash the passphrase with SCB */
				siap_server_passphrase_hash_generate(phash, upass, SIAP_HASH_SIZE);
				/* generate the device tag */
				siap_server_generate_device_tag(&dtag, &dkey, phash);

				/* serialize the tag and store it */
				siap_serialize_device_tag(dstag, &dtag);
				/* this would be stored in a server's secure database along with the server key */
				server_get_path(fpath, sizeof(fpath), SIAP_USER_DATABASE_NAME);
				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)dstag, sizeof(dstag));

				if (res == true)
				{
					server_print_string("server> The database has been saved to ");
					server_print_line(fpath);

					/* encrypt the device key */
					siap_server_encrypt_device_key(&dkey, &skey, phash);

					/* serialize the device key and save it to a file */
					server_get_path(fpath, sizeof(fpath), SIAP_DEVICE_KEY_NAME);
					siap_serialize_device_key(dskey, &dkey);
					res = qsc_fileutils_copy_stream_to_file(fpath, (char*)dskey, sizeof(dskey));

					if (res == true)
					{
						server_print_string("server> The device-key has been saved to ");
						server_print_line(fpath);
						server_print_message("Distribute the device-key to the intended client.");
					}
					else
					{
						siap_log_system_error(siap_error_file_copy_failure);
					}
				}
				else
				{
					siap_log_system_error(siap_error_file_copy_failure);
				}
			}
			else
			{
				siap_log_system_error(siap_error_file_invalid_path);
			}

			/* cleanup */
			qsc_memutils_secure_erase(&dkey, sizeof(dkey));
			qsc_memutils_secure_erase(&dtag, sizeof(dtag));
			qsc_memutils_secure_erase(&skey, sizeof(skey));
			qsc_memutils_secure_erase(upass, sizeof(upass));
			qsc_memutils_secure_erase(dskey, sizeof(dskey));
			qsc_memutils_secure_erase(dstag, sizeof(dstag));
			qsc_memutils_secure_erase(keyid, sizeof(keyid));
			qsc_memutils_secure_erase(phash, sizeof(phash));
			qsc_memutils_secure_erase(sskey, sizeof(sskey));
		}
		else
		{
			siap_log_system_error(siap_error_identity_mismatch);
			server_print_message("Could not create the server-key, aborting startup.");
		}
	}

	return res;
}

int main(void)
{
	server_print_banner();

	if (server_key_exists() == true)
	{
		if (server_key_dialogue() == true)
		{
			server_print_message("Success! The device has been authenticated.");
		}
		else
		{
			server_print_message("Failure! The device authentication has failed.");
		}
	}
	else
	{
		if (server_key_dialogue() == true)
		{
			server_print_message("Success! The server and device keys have been created, restart to test.");
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
