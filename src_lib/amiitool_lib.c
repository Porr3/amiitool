/*
 * (c) 2015-2017 Marcos Del Sol Vives
 * (c) 2016      javiMaD
 *
 * SPDX-License-Identifier: MIT
 */

#include "../amiitool_lib.h"

#include <nfc3d/amiibo.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define NTAG215_SIZE 540

typedef enum _action
{
	ENCRYPT = 0,
	DECRYPT = 1
} Action;

int process(const Action action, const char* pKeyFile, const uint8_t* pOriginal, uint8_t* pModified, const size_t orgSize, const size_t modSize)
{
	nfc3d_amiibo_keys amiiboKeys;
	if (!nfc3d_amiibo_load_keys(&amiiboKeys, pKeyFile))
	{
		fprintf(stderr, "Could not load keys from \"%s\": %s (%d)\n", pKeyFile, strerror(errno), errno);
		return 5;
	}

	if (orgSize < NFC3D_AMIIBO_SIZE)
	{
		fprintf(stderr, "Size of original buffer (%zu) smaller than the minimum expected size of %d byte\n", orgSize, NFC3D_AMIIBO_SIZE);
		return 4;
	}

	if (modSize < NFC3D_AMIIBO_SIZE)
	{
		fprintf(stderr, "Size of modified buffer (%zu) smaller than the minimum expected size of %d byte\n", modSize, NFC3D_AMIIBO_SIZE);
		return 4;
	}

	if(modSize < orgSize)
	{
		fprintf(stderr, "Modified buffer (%zu) is smaller than the Original buffer (%zu)\n", modSize, orgSize);
		return 4;
	}

	memset(pModified, 0, modSize);

	if(action == ENCRYPT)
		nfc3d_amiibo_pack(&amiiboKeys, pOriginal, pModified);
	else if(action == DECRYPT)
	{
		if (!nfc3d_amiibo_unpack(&amiiboKeys, pOriginal, pModified))
		{
			fprintf(stderr, "!!! WARNING !!!: Tag signature was NOT valid\n");
			return 6;
		}
	}

	if (orgSize > NFC3D_AMIIBO_SIZE)
		memcpy(pModified + NFC3D_AMIIBO_SIZE, pOriginal + NFC3D_AMIIBO_SIZE, orgSize - NFC3D_AMIIBO_SIZE);

	return 0;
}

int encrypt(const char* pKeyFile, const uint8_t* pOriginal, uint8_t* pModified, const size_t orgSize, const size_t modSize)
{
	return process(ENCRYPT, pKeyFile, pOriginal, pModified, orgSize, modSize);
}

int decrypt(const char* pKeyFile, const uint8_t* pOriginal, uint8_t* pModified, const size_t orgSize, const size_t modSize)
{
	return process(DECRYPT, pKeyFile, pOriginal, pModified, orgSize, modSize);
}
