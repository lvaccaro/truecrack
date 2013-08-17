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
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"
#include "Crypto.cuh"
#include "Xts.cuh"
#include "Crc.h"
#include "Common/Endian.h"
#include <string.h>
//#ifndef TC_WINDOWS_BOOT
//#include "EncryptionThreadPool.h"
//#endif
#include "Volumes.cuh"
#define max(x, y) (((x) > (y)) ? (x) : (y))

#define min(x, y) (((x) < (y)) ? (x) : (y))



/*


// Cipher configuration
static Cipher Ciphers[] =
{
//								Block Size	Key Size	Key Schedule Size
//	  ID		Name			(Bytes)		(Bytes)		(Bytes)
	{ AES,		"AES",			16,			32,			AES_KS				},
	{ SERPENT,	"Serpent",		16,			32,			140*4				},
	{ TWOFISH,	"Twofish",		16,			32,			TWOFISH_KS			},
#ifndef TC_WINDOWS_BOOT
	{ BLOWFISH,	"Blowfish",		8,			56,			sizeof (BF_KEY)		},	// Deprecated/legacy
	{ CAST,		"CAST5",		8,			16,			sizeof (CAST_KEY)	},	// Deprecated/legacy
	{ TRIPLEDES,"Triple DES",	8,			8*3,		sizeof (TDES_KEY)	},	// Deprecated/legacy
#endif
	{ 0,		0,				0,			0,			0					}
};


// Encryption algorithm configuration
// The following modes have been deprecated (legacy): LRW, CBC, INNER_CBC, OUTER_CBC
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
	{ { BLOWFISH,				0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
	{ { CAST,					0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
	{ { TRIPLEDES,				0 }, { LRW, CBC, 0, 0 },			0 },	// Deprecated/legacy
	{ { BLOWFISH, AES,			0 }, { INNER_CBC, 0, 0, 0 },		0 },	// Deprecated/legacy
	{ { SERPENT, BLOWFISH, AES,	0 }, { INNER_CBC, 0, 0, 0 },		0 },	// Deprecated/legacy
	{ { 0,						0 }, { 0, 0, 0, 0 },				0 }		// Must be all-zero

#else // TC_WINDOWS_BOOT

	// Encryption algorithms available for boot drive encryption
	{ { 0,						0 }, { 0, 0 },		0 },	// Must be all-zero
	{ { AES,					0 }, { XTS, 0 },	1 },
	{ { SERPENT,				0 }, { XTS, 0 },	1 },
	{ { TWOFISH,				0 }, { XTS, 0 },	1 },
	{ { TWOFISH, AES,			0 }, { XTS, 0 },	1 },
	{ { SERPENT, TWOFISH, AES,	0 }, { XTS, 0 },	1 },
	{ { AES, SERPENT,			0 }, { XTS, 0 },	1 },
	{ { AES, TWOFISH, SERPENT,	0 }, { XTS, 0 },	1 },
	{ { SERPENT, TWOFISH,		0 }, { XTS, 0 },	1 },
	{ { 0,						0 }, { 0, 0 },		0 },	// Must be all-zero

#endif

};



// Hash algorithms
static Hash Hashes[] =
{	// ID			Name			Deprecated		System Encryption
	{ RIPEMD160,	"RIPEMD-160",	FALSE,			TRUE },
#ifndef TC_WINDOWS_BOOT
	{ SHA512,		"SHA-512",		FALSE,			FALSE },
	{ WHIRLPOOL,	"Whirlpool",	FALSE,			FALSE },
	{ SHA1,			"SHA-1",		TRUE,			FALSE },	// Deprecated/legacy
#endif
	{ 0, 0, 0 }
};
 */




/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
__device__ int cuCipherInit (int cipher, unsigned char *key, unsigned __int8 *ks)
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
__device__ void cuUint64ToLE16ByteArray (unsigned __int8 *byteBuf, unsigned __int32 highInt32, unsigned __int32 lowInt32)
{
    unsigned __int32 *bufPtr32 = (unsigned __int32 *) byteBuf;
	
    *bufPtr32++ = lowInt32;
    *bufPtr32++ = highInt32;
	
    // We're converting a 64-bit number into a little-endian 16-byte array so we can zero the last 8 bytes
    *bufPtr32++ = 0;
    *bufPtr32 = 0;
}

__device__ void cuEncipherBlock(int cipher, void *data, void *ks)
{
    switch (cipher)
    {
		case AES:
			// In 32-bit kernel mode, due to KeSaveFloatingPointState() overhead, AES instructions can be used only when processing the whole data unit.
			aes_encrypt ((const unsigned char*)data, (unsigned char*)data, (const aes_encrypt_ctx *)ks);
			break;
		case TWOFISH:
			twofish_encrypt ((TwofishInstance *)ks, (const unsigned int *)data, (unsigned int *)data);
			break;
		case SERPENT:
			serpent_encrypt ((const unsigned char *)data, (unsigned char *)data, (unsigned char *)ks);
			break;
		default:
			;//TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
    }
}

__device__ void cuDecipherBlock(int cipher, void *data, void *ks)
{
    switch (cipher)
    {
#ifndef TC_WINDOWS_BOOT
			
		case AES:
			aes_decrypt ((const unsigned char*)data, (unsigned char*)data, (const aes_decrypt_ctx *) ((char *) ks + sizeof(aes_decrypt_ctx)));
			break;
#else
		case AES:
			aes_decrypt ((unsigned char*)data, (unsigned char*)data, ((const aes_decrypt_ctx *))ks);
			break;
#endif
		case SERPENT:
			serpent_decrypt ((const unsigned char *)data, (unsigned char *)data, (unsigned char *)ks);
			break;
		case TWOFISH:
			twofish_decrypt ((TwofishInstance *)ks, (const unsigned int *)data, (unsigned int *)data);
			break;
		default:
			;//TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
    }
}

__device__ int cuEAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
    int retVal = ERR_SUCCESS;
	
    if (ea == 0)
        return ERR_CIPHER_INIT_FAILURE;
    //for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
    //{
    switch (cuCipherInit (ea, key, ks))
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
}

__device__ BOOL cuEAInitMode (PCRYPTO_INFO ci)
{
    // Secondary key schedule
    if (cuEAInit (ci->ea, ci->km2, ci->ks2) != ERR_SUCCESS)
        return FALSE;
    return TRUE;
}

