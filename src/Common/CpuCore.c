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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <time.h>

#include "Volumes.h"
#include "Tcdefs.h"
#include "Utils.h"
#include "Crypto.h"

#include "Core.h"
#include "CpuCore.h"
#include "Pkcs5.h"
#include "CpuAes.h"

enum
{
    UNDEFINED,
    SUCCESS,
    ERR_OUT_OF_MEMORY,
    ERR_CIPHER_INIT,
    ERR_MODE_INIT,
    ERR_MAGIC_TRUE,
    ERR_VERSION_REQUIRED,
    ERR_CRC_HEADER_FIELDS,
    ERR_CRC_KEY_SET
};
#define max(x, y) (((x) > (y)) ? (x) : (y))
#define min(x, y) (((x) < (y)) ? (x) : (y))
int cpu_GetMaxPkcs5OutSize (void)
{
    int size = 32;// Sizes of primary + secondary keys
    size = max (size, 32 * 2);	// Sizes of primary + secondary keys
    //size = max (size, cpu_EAGetLargestKeyForMode (XTS) * 2);	// Sizes of primary + secondary keys
    return size;
}




int cpu_Core_charset(unsigned char *encryptedHeader, unsigned char *CORE_charset, int wordlength,int verbose, int keyDerivationFunction) {
    // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
    int i,j,value=-1,found;
    unsigned char salt[PKCS5_SALT_SIZE];
    unsigned char headerKey[256]={0};
    unsigned char masterKey[256]={0};
    int length;
    unsigned char word[MAXWORDSIZE];
    memcpy (salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    
    uint64 maxcombination=1,count=0;
    for (i=0;i<wordlength;i++)
       maxcombination*= strlen(CORE_charset);
    

    for (count=0;count<maxcombination;count++){
		computePwd (count, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
		word[wordlength]='\0';
	
		if (verbose){
			printf("%d - %d/",wordlength,count);
			printf("%lu >> ",maxcombination);
			 for (i=0;i<wordlength;i++)
				printf("%c",word[i]);
			 printf(" : ");
		}
 
    	if(keyDerivationFunction==RIPEMD160)
    		derive_key_ripemd160 ( word, wordlength+1, salt, PKCS5_SALT_SIZE, 2000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else if(keyDerivationFunction==SHA512)
    		derive_key_sha512 (  word, wordlength+1, salt, PKCS5_SALT_SIZE, 2000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else if(keyDerivationFunction==WHIRLPOOL)
    		derive_key_whirlpool (  word, wordlength+1, salt, PKCS5_SALT_SIZE, 2000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else{
    		perror("Key derivation function not supported");
    		return;
    	}
    		   
    
    
		value=cpu_Xts(encryptedHeader,headerKey,cpu_GetMaxPkcs5OutSize(), masterKey, &length);
			
		if (value==SUCCESS) {
			if (verbose)
				printf("MATCH\n");
			return count;
		}else{
			if (verbose)
				printf("NO MATCH\n");
		}
        }
	return -1;
}



void cpu_Core_dictionary(int blocksize, unsigned char *encryptedHeader, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int keyDerivationFunction) {
    // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
    int i,j,value=-1,found;
    unsigned char salt[PKCS5_SALT_SIZE];
    unsigned char headerKey[MASTER_KEYDATA_SIZE];
    memcpy (salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    
     
    found=0;
    for (i=0;i<blocksize && found==0;i++) {

    	if(keyDerivationFunction==RIPEMD160)
    		derive_key_ripemd160 ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 2000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else if(keyDerivationFunction==SHA512)
    		derive_key_sha512 ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 1000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else if(keyDerivationFunction==WHIRLPOOL)
    		derive_key_whirlpool ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 1000, headerKey, cpu_GetMaxPkcs5OutSize ());
    	else{
    		perror("Key derivation function not supported");
    		return;
    	}

        value=cpu_Xts(encryptedHeader,headerKey,cpu_GetMaxPkcs5OutSize(), NULL, NULL);

	result[i]=NOMATCH;
	if (value==SUCCESS) {
	    result[i]=MATCH;
	    found=1;
        }
    }
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
    default:
        TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
    }
}



// Encrypts or decrypts all blocks in the buffer in XTS mode. For descriptions of the input parameters,
// see the 64-bit version of EncryptBufferXTS().
void cpu_EncryptDecryptBufferXTS32 (const unsigned __int8 *buffer,
                                    TC_LARGEST_COMPILER_UINT length,
                                    const UINT64_STRUCT *startDataUnitNo,
                                    unsigned int startBlock,
                                    unsigned __int8 *ks,
                                    unsigned __int8 *ks2,
                                    int cipher,
                                    BOOL decryption)
{

    TC_LARGEST_COMPILER_UINT blockCount;
    UINT64_STRUCT dataUnitNo;
    unsigned int block;
    unsigned int endBlock;
    unsigned __int8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
    unsigned __int8 whiteningValue [BYTES_PER_XTS_BLOCK];
    unsigned __int8 finalCarry;
    unsigned __int32 *whiteningValuePtr32;
    unsigned __int32 *finalDwordWhiteningValuePtr;
    unsigned __int32 *bufPtr32;
    bufPtr32 = (unsigned __int32 *) buffer;
    whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;
    finalDwordWhiteningValuePtr = whiteningValuePtr32 + sizeof (whiteningValue) / sizeof (*whiteningValuePtr32) - 1;


// Store the 64-bit data unit number in a way compatible with non-64-bit environments/platforms
    dataUnitNo.HighPart = startDataUnitNo->HighPart;
    dataUnitNo.LowPart = startDataUnitNo->LowPart;

    blockCount = length / BYTES_PER_XTS_BLOCK;

    // Convert the 64-bit data unit number into a little-endian 16-byte array.
    // (Passed as two 32-bit integers for compatibility with non-64-bit environments/platforms.)
    cpu_Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);

    // Generate whitening values for all blocks in the buffer
    while (blockCount > 0)
    {

        if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
            endBlock = startBlock + (unsigned int) blockCount;
        else
            endBlock = BLOCKS_PER_XTS_DATA_UNIT;

// Encrypt the data unit number using the secondary key (in order to generate the first
        // whitening value for this data unit)
        memcpy (whiteningValue, byteBufUnitNo, BYTES_PER_XTS_BLOCK);
        cpu_EncipherBlock (cipher, whiteningValue, ks2);

        // Generate (and apply) subsequent whitening values for blocks in this data unit and
        // encrypt/decrypt all relevant blocks in this data unit
        for (block = 0; block < endBlock; block++)
        {
            if (block >= startBlock)
            {
                whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;

                // Whitening
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32 ^= *whiteningValuePtr32;

                bufPtr32 -= BYTES_PER_XTS_BLOCK / sizeof (*bufPtr32) - 1;

                // Actual encryption/decryption
                if (decryption)
                    cpu_DecipherBlock (cipher, bufPtr32, ks);
                else
                    cpu_EncipherBlock (cipher, bufPtr32, ks);

                whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;

                // Whitening
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32++ ^= *whiteningValuePtr32++;
                *bufPtr32++ ^= *whiteningValuePtr32;
            }

            // Derive the next whitening value

            finalCarry = 0;

            for (whiteningValuePtr32 = finalDwordWhiteningValuePtr;
                    whiteningValuePtr32 >= (unsigned __int32 *) whiteningValue;
                    whiteningValuePtr32--)
            {
                if (*whiteningValuePtr32 & 0x80000000)	// If the following shift results in a carry
                {
                    if (whiteningValuePtr32 != finalDwordWhiteningValuePtr)	// If not processing the highest double word
                    {
                        // A regular carry
                        *(whiteningValuePtr32 + 1) |= 1;
                    }
                    else
                    {
                        // The highest byte shift will result in a carry
                        finalCarry = 135;
                    }
                }

                *whiteningValuePtr32 <<= 1;
            }

            whiteningValue[0] ^= finalCarry;
        }

        blockCount -= endBlock - startBlock;
        startBlock = 0;

        // Increase the data unit number by one
        if (!++dataUnitNo.LowPart)
        {
            dataUnitNo.HighPart++;
        }

        // Convert the 64-bit data unit number into a little-endian 16-byte array.
        cpu_Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
    }

    FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
}

// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS() above.
void cpu_EncryptBufferXTS (unsigned __int8 *buffer,
                           TC_LARGEST_COMPILER_UINT length,
                           const UINT64_STRUCT *startDataUnitNo,
                           unsigned int startCipherBlockNo,
                           unsigned __int8 *ks,
                           unsigned __int8 *ks2,
                           int cipher)
{
    // Encrypt all plaintext blocks in the buffer
    cpu_EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, FALSE);
}


// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS().
void cpu_DecryptBufferXTS (unsigned __int8 *buffer,
                           TC_LARGEST_COMPILER_UINT length,
                           const UINT64_STRUCT *startDataUnitNo,
                           unsigned int startCipherBlockNo,
                           unsigned __int8 *ks,
                           unsigned __int8 *ks2,
                           int cipher)
{
    // Decrypt all ciphertext blocks in the buffer
    cpu_EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, TRUE);
}

void cpu_DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
    UINT64_STRUCT dataUnitNo;
    int cipher;

    // When encrypting/decrypting a buffer (typically a volume header) the sequential number
    // of the first XTS data unit in the buffer is always 0 and the start of the buffer is
    // always assumed to be aligned with the start of the data unit 0.
    dataUnitNo.LowPart = 0;
    dataUnitNo.HighPart = 0;

    cpu_DecryptBufferXTS (buf, len, &dataUnitNo, 0, cryptoInfo->ks, cryptoInfo->ks2, AES);
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
        if (aes_set_key (key, (length_type) CipherGetKeySize(AES), (aes_context *) ks) != 0)
            return ERR_CIPHER_INIT_FAILURE;
#endif
        break;


    default:
        // Unknown/wrong cipher ID
        return ERR_CIPHER_INIT_FAILURE;
    }

    return retVal;
}

int cpu_EAInit (int ea, unsigned char *key, unsigned __int8 *ks)
{
    int c, retVal = ERR_SUCCESS;

    if (ea == 0)
        return ERR_CIPHER_INIT_FAILURE;
    c=AES;
    //for (c = EAGetFirstCipher (ea); c != 0; c = EAGetNextCipher (ea, c))
    //{
    switch (cpu_CipherInit (c, key, ks))
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

int cpu_Xts(char *encryptedHeader, char *headerKey, int headerKey_length, char *masterKey, int *masterKey_length) {
    BOOL ReadVolumeHeaderRecoveryMode = FALSE;
    char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
    PCRYPTO_INFO cryptoInfo;
    uint16 headerVersion;
    int status = ERR_PARAMETER_INCORRECT;
    int primaryKeyOffset=0;
    CRYPTO_INFO cryptoInfo_struct;

    //int pkcs5PrfCount = LAST_PRF_ID - FIRST_PRF_ID + 1;
    int i,j;

    cryptoInfo=&cryptoInfo_struct;
    memset (cryptoInfo, 0, sizeof (CRYPTO_INFO));
    if (cryptoInfo == NULL)
        return ERR_OUT_OF_MEMORY;


    // Support only XTS
    cryptoInfo->mode= XTS ;
    cryptoInfo->ea=AES;

    int blockSize;
    blockSize = 16;
    status = cpu_EAInit (cryptoInfo->ea, headerKey + primaryKeyOffset, cryptoInfo->ks);
    if (status == ERR_CIPHER_INIT_FAILURE)
        return ERR_CIPHER_INIT;
    // Init objects related to the mode of operation

// Copy the secondary key (if cascade, multiple concatenated)
    //memcpy (cryptoInfo->km2, headerKey + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
    memcpy (cryptoInfo->km2, headerKey + 32, 32);
    // Secondary key schedule
    if (!cpu_EAInitMode (cryptoInfo)) {
        return ERR_MODE_INIT;
    }

    // Copy the header for decryption
    memcpy (header, encryptedHeader, 512*sizeof(unsigned char));

    // Try to decrypt header
    cpu_DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

    // Magic 'TRUE'
    if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x54525545)
        return ERR_MAGIC_TRUE;

    // Header version
    headerVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION);
    if (headerVersion > VOLUME_HEADER_VERSION) {
        return ERR_VERSION_REQUIRED;
    }
    // Check CRC of the header fields
    if (!ReadVolumeHeaderRecoveryMode
            && headerVersion >= 4
            && GetHeaderField32 (header, TC_HEADER_OFFSET_HEADER_CRC) != GetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
        return ERR_CRC_HEADER_FIELDS;

    // Required program version
    //cryptoInfo->RequiredProgramVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_REQUIRED_VERSION);
    //cryptoInfo->LegacyVolume = cryptoInfo->RequiredProgramVersion < 0x600;

    // Check CRC of the key set
    if (!ReadVolumeHeaderRecoveryMode
            && GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != GetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
        return ERR_CRC_KEY_SET;

    /*
    // Now we have the correct password, cipher, hash algorithm, and volume type
    // Check the version required to handle this volume
    if (cryptoInfo->RequiredProgramVersion > VERSION_NUM){
    	return ERR_NEW_VERSION_REQUIRED;
    }

    // Header version
    cryptoInfo->HeaderVersion = headerVersion;

    // Volume creation time (legacy)
    cryptoInfo->volume_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_CREATION_TIME).Value;

    // Header creation time (legacy)
    cryptoInfo->header_creation_time = GetHeaderField64 (header, TC_HEADER_OFFSET_MODIFICATION_TIME).Value;

    // Hidden volume size (if any)
    cryptoInfo->hiddenVolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_HIDDEN_VOLUME_SIZE).Value;

    // Hidden volume status
    cryptoInfo->hiddenVolume = (cryptoInfo->hiddenVolumeSize != 0);

    // Volume size
    cryptoInfo->VolumeSize = GetHeaderField64 (header, TC_HEADER_OFFSET_VOLUME_SIZE);

    // Encrypted area size and length
    cryptoInfo->EncryptedAreaStart = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_START);
    cryptoInfo->EncryptedAreaLength = GetHeaderField64 (header, TC_HEADER_OFFSET_ENCRYPTED_AREA_LENGTH);

    // Flags
    cryptoInfo->HeaderFlags = GetHeaderField32 (header, TC_HEADER_OFFSET_FLAGS);

    // Sector size
    if (headerVersion >= 5)
    	cryptoInfo->SectorSize = GetHeaderField32 (header, TC_HEADER_OFFSET_SECTOR_SIZE);
    else
    	cryptoInfo->SectorSize = TC_SECTOR_SIZE_LEGACY;

    if (cryptoInfo->SectorSize < TC_MIN_VOLUME_SECTOR_SIZE
    	|| cryptoInfo->SectorSize > TC_MAX_VOLUME_SECTOR_SIZE
    	|| cryptoInfo->SectorSize % ENCRYPTION_DATA_UNIT_SIZE != 0){
    	return ERR_PARAMETER_INCORRECT;
    }
*/
    // Master key data
    if (masterKey!=NULL && masterKey_length!=NULL) {
        memcpy (masterKey, header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE);
        *masterKey_length= 64;
    }

    return SUCCESS;
}

