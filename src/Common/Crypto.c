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

int cpu_EAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
    int c, retVal = ERR_SUCCESS;
	
    if (ea == 0)
        return ERR_CIPHER_INIT_FAILURE;
    //for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
    //{
    switch (cpu_CipherInit (ea, key, ks))
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

BOOL cpu_EAInitMode (PCRYPTO_INFO ci)
{
    // Secondary key schedule
    if (cpu_EAInit (ci->ea, ci->km2, ci->ks2) != ERR_SUCCESS)
        return FALSE;
    return TRUE;
}

/* Return values: 0 = success, ERR_CIPHER_INIT_FAILURE (fatal), ERR_CIPHER_INIT_WEAK_KEY (non-fatal) */
int cpu_CipherInit (int cipher, unsigned char *key, unsigned __int8 *ks)
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
void cpu_Uint64ToLE16ByteArray (unsigned __int8 *byteBuf, unsigned __int32 highInt32, unsigned __int32 lowInt32)
{
    unsigned __int32 *bufPtr32 = (unsigned __int32 *) byteBuf;
	
    *bufPtr32++ = lowInt32;
    *bufPtr32++ = highInt32;
	
    // We're converting a 64-bit number into a little-endian 16-byte array so we can zero the last 8 bytes
    *bufPtr32++ = 0;
    *bufPtr32 = 0;
}

void cpu_EncipherBlock(int cipher, void *data, void *ks)
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

void cpu_DecipherBlock(int cipher, void *data, void *ks)
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
