/*
 * Copyright (C)  2011  Luca Vaccaro
 * Based on TrueCrypt, freely available at http://www.truecrypt.org/
 *
 * TrueCrack is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
/*
 Copyright (c) 2008-2010 TrueCrypt Developers Association. All rights reserved.
 
 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.
 */

/* If native 64-bit data types are not available, define TC_NO_COMPILER_INT64.
 
 For big-endian platforms define BYTE_ORDER as BIG_ENDIAN. */

#include "Crypto.h"
#include "Core.h"

 // Cipher configuration
static Cipher Ciphers[] =
{
//								Block Size	Key Size	Key Schedule Size
//	  ID		Name			(Bytes)		(Bytes)		(Bytes)
	{ AES,		"AES",			16,			32,			AES_KS				},
	{ SERPENT,	"Serpent",		16,			32,			140*4				},
	{ TWOFISH,	"Twofish",		16,			32,			TWOFISH_KS			},
//	{ BLOWFISH,	"Blowfish",		8,			56,			sizeof (BF_KEY)		},	// Deprecated/legacy
//	{ CAST,		"CAST5",		8,			16,			sizeof (CAST_KEY)	},	// Deprecated/legacy
//	{ TRIPLEDES,"Triple DES",	8,			8*3,		sizeof (TDES_KEY)	},	// Deprecated/legacy
	{ 0,		0,				0,			0,			0					}
};



static EncryptionAlgorithm EncryptionAlgorithms[] =
{
	//  Cipher(s)                     Modes						FormatEnabled

#ifndef TC_WINDOWS_BOOT

	{ { 0,						0 }, { 0, 0, 0, 0 },				0 },	// Must be all-zero
	{ { AES,					0 }, { XTS, LRW, CBC, 0 },			1 },
	{ { SERPENT,				0 }, { XTS, LRW, CBC, 0 },			1 },
	{ { TWOFISH,				0 }, { XTS, LRW, CBC, 0 },			1 },
	{ { TWOFISH, AES,			0 }, { XTS, LRW, OUTER_CBC, 0 },	1 },
	{ { SERPENT, TWOFISH, AES,	0 }, { XTS, LRW, OUTER_CBC, 0 },	1 },
	{ { AES, SERPENT,			0 }, { XTS, LRW, OUTER_CBC, 0 },	1 },
	{ { AES, TWOFISH, SERPENT,	0 }, { XTS, LRW, OUTER_CBC, 0 },	1 },
	{ { SERPENT, TWOFISH,		0 }, { XTS, LRW, OUTER_CBC, 0 },	1 },
//	{ { BLOWFISH,				0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
//	{ { CAST,					0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
//	{ { TRIPLEDES,				0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
//	{ { BLOWFISH, AES,			0 }, { INNER_CBC, 0, 0, 0 },		0 },	// Deprecated/legacy
//	{ { SERPENT, BLOWFISH, AES,	0 }, { INNER_CBC, 0, 0, 0 },		0 },	// Deprecated/legacy
	{ { 0,						0 }, { 0, 0, 0, 0 },				0 }		// Must be all-zero
#endif
};
/*
int EAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
    int c, retVal = ERR_SUCCESS;
	
    if (ea == 0)
        return ERR_CIPHER_INIT_FAILURE;
    //for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
    //{
    switch (CipherInit (ea, key, ks))
    {
		case ERR_CIPHER_INIT_FAILURE:
			return ERR_CIPHER_INIT_FAILURE;
			
		case ERR_CIPHER_INIT_WEAK_KEY:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;              // Non-fatal error
			break;
    }
	
    //key += CipherGetKeySize (c);
    //ks += CipherGetKeyScheduleSize (c);
    //}
    return retVal;
}*/



// Ciphers support

Cipher *CipherGet (int id)
{
	int i;
	for (i = 0; Ciphers[i].Id != 0; i++)
		if (Ciphers[i].Id == id)
			return &Ciphers[i];

	return NULL;
}
int CipherGetKeySize (int cipherId)
{
	return CipherGet (cipherId) -> KeySize;
}

int CipherGetKeyScheduleSize (int cipherId)
{
	return CipherGet (cipherId) -> KeyScheduleSize;
}
int CipherGetBlockSize (int cipherId)
{
	return CipherGet (cipherId) -> BlockSize;
}

// Encryption algorithms support

int EAGetFirst ()
{
	return 1;
}

// Returns number of EAs
int EAGetCount (void)
{
	int ea, count = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		count++;
	}
	return count;
}

int EAGetNext (int previousEA)
{
	int id = previousEA + 1;
	if (EncryptionAlgorithms[id].Ciphers[0] != 0) return id;
	return 0;
}


// Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal)
int EAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
	int c, retVal = ERR_SUCCESS;

	if (ea == 0)
		return ERR_CIPHER_INIT_FAILURE;

	for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
	{
		switch (CipherInit (c, key, ks))
		{
		case ERR_CIPHER_INIT_FAILURE:
			return ERR_CIPHER_INIT_FAILURE;

		case ERR_CIPHER_INIT_WEAK_KEY:
			retVal = ERR_CIPHER_INIT_WEAK_KEY;		// Non-fatal error
			break;
		}

		key += CipherGetKeySize (c);
		ks += CipherGetKeyScheduleSize (c);
	}
	return retVal;
}



BOOL EAInitMode (PCRYPTO_INFO ci)
{
    // Secondary key schedule
    if (EAInit (ci->ea, ci->k2, ci->ks2) != ERR_SUCCESS)
        return FALSE;
    return TRUE;
}/*
BOOL EAInitMode (PCRYPTO_INFO ci)
{
	switch (ci->mode)
	{
	case XTS:
		// Secondary key schedule
		if (EAInit (ci->ea, ci->k2, ci->ks2) != ERR_SUCCESS)
			return FALSE;

		// Note: XTS mode could potentially be initialized with a weak key causing all blocks in one data unit
		on the volume to be tweaked with zero tweaks (i.e. 512 bytes of the volume would be encrypted in ECB
		mode). However, to create a TrueCrypt volume with such a weak key, each human being on Earth would have
		to create approximately 11,378,125,361,078,862 (about eleven quadrillion) TrueCrypt volumes (provided 
		that the size of each of the volumes is 1024 terabytes). 
		break;

	case LRW:
		switch (CipherGetBlockSize (EAGetFirstCipher (ci->ea)))
		{
		case 8:
			// Deprecated/legacy 
			return Gf64TabInit (ci->k2, &ci->gf_ctx);

		case 16:
			return Gf128Tab64Init (ci->k2, &ci->gf_ctx);

		default:
			TC_THROW_FATAL_EXCEPTION;
		}

		break;

	case CBC:
	case INNER_CBC:
	case OUTER_CBC:
		// The mode does not need to be initialized or is initialized elsewhere 
		return TRUE;

	default:		
		// Unknown/wrong ID
		TC_THROW_FATAL_EXCEPTION;
	}
	return TRUE;
}*/



// Returns sum of key sizes of all ciphers of the EA (in bytes)
int EAGetKeySize (int ea)
{
	int i = EAGetFirstCipher (ea);
	int size = CipherGetKeySize (i);

	while (i = EAGetNextCipher (ea, i))
	{
		size += CipherGetKeySize (i);
	}

	return size;
}


// Returns the first mode of operation of EA
int EAGetFirstMode (int ea)
{
	return (EncryptionAlgorithms[ea].Modes[0]);
}


int EAGetNextMode (int ea, int previousModeId)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Modes[i++])
	{
		if (c == previousModeId) 
			return EncryptionAlgorithms[ea].Modes[i];
	}

	return 0;
}




// Returns sum of key schedule sizes of all ciphers of the EA
int EAGetKeyScheduleSize (int ea)
{
	int i = EAGetFirstCipher(ea);
	int size = CipherGetKeyScheduleSize (i);

	while (i = EAGetNextCipher(ea, i))
	{
		size += CipherGetKeyScheduleSize (i);
	}

	return size;
}


// Returns the largest key size needed by an EA for the specified mode of operation
int EAGetLargestKeyForMode (int mode)
{
	int ea, key = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		if (!EAIsModeSupported (ea, mode))
			continue;

		if (EAGetKeySize (ea) >= key)
			key = EAGetKeySize (ea);
	}
	return key;
}


// Returns the largest key needed by any EA for any mode
int EAGetLargestKey ()
{
	int ea, key = 0;

	for (ea = EAGetFirst (); ea != 0; ea = EAGetNext (ea))
	{
		if (EAGetKeySize (ea) >= key)
			key = EAGetKeySize (ea);
	}

	return key;
}


// Returns number of ciphers in EA
int EAGetCipherCount (int ea)
{
	int i = 0;
	while (EncryptionAlgorithms[ea].Ciphers[i++]);

	return i - 1;
}


int EAGetFirstCipher (int ea)
{
	return EncryptionAlgorithms[ea].Ciphers[0];
}


int EAGetLastCipher (int ea)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++]);

	return EncryptionAlgorithms[ea].Ciphers[i - 2];
}


int EAGetNextCipher (int ea, int previousCipherId)
{
	int c, i = 0;
	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i];
	}

	return 0;
}


int EAGetPreviousCipher (int ea, int previousCipherId)
{
	int c, i = 0;

	if (EncryptionAlgorithms[ea].Ciphers[i++] == previousCipherId)
		return 0;

	while (c = EncryptionAlgorithms[ea].Ciphers[i++])
	{
		if (c == previousCipherId) 
			return EncryptionAlgorithms[ea].Ciphers[i - 2];
	}

	return 0;
}


int EAIsFormatEnabled (int ea)
{
	return EncryptionAlgorithms[ea].FormatEnabled;
}


// Returns TRUE if the mode of operation is supported for the encryption algorithm
BOOL EAIsModeSupported (int ea, int testedMode)
{
	int mode;

	for (mode = EAGetFirstMode (ea); mode != 0; mode = EAGetNextMode (ea, mode))
	{
		if (mode == testedMode)
			return TRUE;
	}
	return FALSE;
}










/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
int CipherInit (int cipher, unsigned char *key, unsigned __int8 *ks)
{
    int retVal = ERR_SUCCESS;
	
    switch (cipher)
    {
		case AES:
#ifndef TC_WINDOWS_BOOT
			if (aes_encrypt_key256 (key, (aes_encrypt_ctx *) ks) != EXIT_SUCCESS)
				return ERR_CIPHER_INIT_FAILURE;
			
			if (aes_decrypt_key256 (key, (aes_decrypt_ctx *) (ks + sizeof(aes_encrypt_ctx))) != EXIT_SUCCESS)
				return ERR_CIPHER_INIT_FAILURE;
#else
			if (aes_set_key (key, (length_type) 32, (aes_context *) ks) != 0)
				return ERR_CIPHER_INIT_FAILURE;
#endif
			break;
			
		case SERPENT:
			serpent_set_key (key, 32 * 8, ks);
			break;
			
		case TWOFISH:
			twofish_set_key ((TwofishInstance *)ks, (const u4byte *)key, 32 * 8);
			break;
		default:
			// Unknown/wrong cipher ID
			return ERR_CIPHER_INIT_FAILURE;
    }
	
    return retVal;
}

// Converts a 64-bit unsigned integer (passed as two 32-bit integers for compatibility with non-64-bit
// environments/platforms) into a little-endian 16-byte array.
void Uint64ToLE16ByteArray (unsigned __int8 *byteBuf, unsigned __int32 highInt32, unsigned __int32 lowInt32)
{
    unsigned __int32 *bufPtr32 = (unsigned __int32 *) byteBuf;
	
    *bufPtr32++ = lowInt32;
    *bufPtr32++ = highInt32;
	
    // We're converting a 64-bit number into a little-endian 16-byte array so we can zero the last 8 bytes
    *bufPtr32++ = 0;
    *bufPtr32 = 0;
}

void EncipherBlock(int cipher, void *data, void *ks)
{
    switch (cipher)
    {
		case AES:
			// In 32-bit kernel mode, due to KeSaveFloatingPointState() overhead, AES instructions can be used only when processing the whole data unit.
			aes_encrypt (data, data, ks);
			break;
		case TWOFISH:		twofish_encrypt (ks, data, data); break;
		case SERPENT:		serpent_encrypt (data, data, ks); break;
		default:
			TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
    }
}

void DecipherBlock(int cipher, void *data, void *ks)
{
    switch (cipher)
    {
#ifndef TC_WINDOWS_BOOT
			
		case AES:
			aes_decrypt (data, data, (void *) ((char *) ks + sizeof(aes_encrypt_ctx)));
			break;
#else
		case AES:
			aes_decrypt (data, data, ks);
			break;
#endif
		case SERPENT:	serpent_decrypt (data, data, ks); break;
		case TWOFISH:	twofish_decrypt (ks, data, data); break;
		default:
			TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
    }
}
