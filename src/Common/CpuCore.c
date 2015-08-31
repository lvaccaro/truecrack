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

#include "Serpent.h"
#include "Twofish.h"

enum
{
	UNDEFINED=0,
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
int GetMaxPkcs5OutSize (void)
{
	int size = 32;// Sizes of primary + secondary keys
	size = max (size, 32 * 2);	// Sizes of primary + secondary keys
	size = max (size, EAGetLargestKeyForMode (XTS) * 2);	// Sizes of primary + secondary keys
	return size;
}




int Core_charset(enum CORE_EncryptionAlgorithms encryptionAlgorithm,unsigned char *encryptedHeader, unsigned char *CORE_charset, unsigned char *word_, int wordlength, int keyDerivationFunction, unsigned char* prefix) {
	// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
	int i,j,value=-1,found;
	unsigned char salt[PKCS5_SALT_SIZE];
	unsigned char headerKey[256]={0};
	unsigned char masterKey[256]={0};
	int length;
	memcpy (salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);

	unsigned char word[MAXWORDSIZE];
	if(prefix!=NULL){
		unsigned char tmp[MAXWORDSIZE];
                strncpy(word,prefix,strlen(prefix));
                strncpy(word+strlen(prefix),word_,wordlength);
                wordlength+=strlen(prefix);
	}else
		strncpy(word,word_,wordlength);


	uint64 maxcombination=1,count=0;
	for (i=0;i<wordlength;i++)
		maxcombination*= strlen(CORE_charset);

	if(keyDerivationFunction==RIPEMD160)
		derive_key_ripemd160 ( word, wordlength+1, salt, PKCS5_SALT_SIZE, 2000, headerKey, GetMaxPkcs5OutSize ());
	else if(keyDerivationFunction==SHA512)
		derive_key_sha512 (  word, wordlength+1, salt, PKCS5_SALT_SIZE, 1000, headerKey, GetMaxPkcs5OutSize ());
	else if(keyDerivationFunction==WHIRLPOOL)
		derive_key_whirlpool (  word, wordlength+1, salt, PKCS5_SALT_SIZE, 1000, headerKey, GetMaxPkcs5OutSize ());
	else{
		perror("Key derivation function not supported");
		return 0;
	}

	value=Xts(encryptionAlgorithm,encryptedHeader,headerKey,GetMaxPkcs5OutSize(), masterKey, &length);

	if (value==SUCCESS)
		return 1;
	return 0;
}



void Core_dictionary(enum CORE_EncryptionAlgorithms encryptionAlgorithm,  int blocksize, unsigned char *encryptedHeader, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int keyDerivationFunction) {
	// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
	int i,j,value=-1,found;
	unsigned char salt[PKCS5_SALT_SIZE];
	unsigned char headerKey[MASTER_KEYDATA_SIZE]={0};
	memcpy (salt, encryptedHeader + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);


	found=0;
	for (i=0;i<blocksize && found==0;i++) {

		if(keyDerivationFunction==RIPEMD160)
			derive_key_ripemd160 ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 2000, headerKey, GetMaxPkcs5OutSize ());
		else if(keyDerivationFunction==SHA512)
			derive_key_sha512 ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 1000, headerKey, GetMaxPkcs5OutSize ());
		else if(keyDerivationFunction==WHIRLPOOL)
			derive_key_whirlpool ( blockPwd+blockPwd_init[i], blockPwd_length[i], salt, PKCS5_SALT_SIZE, 1000, headerKey, GetMaxPkcs5OutSize ());
		else{
			perror("Key derivation function not supported");
			return;
		}
/*
	printf("headerKey[%d]: ",GetMaxPkcs5OutSize()); 
	for (int i=0;i<MASTER_KEYDATA_SIZE;i++)
		printf("%02x",(unsigned short)headerKey[i]);
	printf("\n");
	*/

		result[i]=Xts(encryptionAlgorithm,encryptedHeader,headerKey,GetMaxPkcs5OutSize(), NULL, NULL);
		if (result[i]==SUCCESS)
			found=1;
	}
}




// Encrypts or decrypts all blocks in the buffer in XTS mode. For descriptions of the input parameters,
// see the 64-bit version of EncryptBufferXTS().
void EncryptDecryptBufferXTS32 (const unsigned __int8 *buffer,
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
	Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);

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
		EncipherBlock (cipher, whiteningValue, ks2);

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
					DecipherBlock (cipher, bufPtr32, ks);
				else
					EncipherBlock (cipher, bufPtr32, ks);

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
		Uint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
	}

	FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
}

// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS() above.
void EncryptBufferXTS (unsigned __int8 *buffer,
		TC_LARGEST_COMPILER_UINT length,
		const UINT64_STRUCT *startDataUnitNo,
		unsigned int startCipherBlockNo,
		unsigned __int8 *ks,
		unsigned __int8 *ks2,
		int cipher)
{
	// Encrypt all plaintext blocks in the buffer
	EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, FALSE);
}


// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS().
void DecryptBufferXTS (unsigned __int8 *buffer,
		TC_LARGEST_COMPILER_UINT length,
		const UINT64_STRUCT *startDataUnitNo,
		unsigned int startCipherBlockNo,
		unsigned __int8 *ks,
		unsigned __int8 *ks2,
		int cipher)
{
	// Decrypt all ciphertext blocks in the buffer
	EncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, TRUE);
}
/*
void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	UINT64_STRUCT dataUnitNo;
	int cipher;

	// When encrypting/decrypting a buffer (typically a volume header) the sequential number
	// of the first XTS data unit in the buffer is always 0 and the start of the buffer is
	// always assumed to be aligned with the start of the data unit 0.
	dataUnitNo.LowPart = 0;
	dataUnitNo.HighPart = 0;

	DecryptBufferXTS (buf, len, &dataUnitNo, 0, cryptoInfo->ks, cryptoInfo->ks2, cryptoInfo->ea);
}
*/

// DecryptBuffer
//
// buf:  data to be decrypted; the start of the buffer is assumed to be aligned with the start of a data unit.
// len:  number of bytes to decrypt; must be divisible by the block size (for cascaded ciphers, divisible 
//       by the largest block size used within the cascade)
void DecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	switch (cryptoInfo->mode)
	{
	case XTS:
		{
			unsigned __int8 *ks = cryptoInfo->ks + EAGetKeyScheduleSize (cryptoInfo->ea);
			unsigned __int8 *ks2 = cryptoInfo->ks2 + EAGetKeyScheduleSize (cryptoInfo->ea);
			UINT64_STRUCT dataUnitNo;
			int cipher;

			// When encrypting/decrypting a buffer (typically a volume header) the sequential number
			// of the first XTS data unit in the buffer is always 0 and the start of the buffer is
			// always assumed to be aligned with the start of the data unit 0.
			dataUnitNo.LowPart = 0;
			dataUnitNo.HighPart = 0;

			for (cipher = EAGetLastCipher (cryptoInfo->ea);
				cipher != 0;
				cipher = EAGetPreviousCipher (cryptoInfo->ea, cipher))
			{
				ks -= CipherGetKeyScheduleSize (cipher);
				ks2 -= CipherGetKeyScheduleSize (cipher);

				DecryptBufferXTS (buf, len, &dataUnitNo, 0, ks, ks2, cipher);
			}
		}
		break;
	}
}




int Xts(enum CORE_EncryptionAlgorithms encryptionAlgorithm, char *encryptedHeader, char *headerKey, int headerKey_length, char *masterKey, int *masterKey_length) {
	BOOL ReadVolumeHeaderRecoveryMode = FALSE;
	char header[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
	PCRYPTO_INFO cryptoInfo;
	uint16 headerVersion;
	int status = ERR_PARAMETER_INCORRECT;
	int primaryKeyOffset=0; // Test all available modes of operation: default = 0
	CRYPTO_INFO cryptoInfo_struct;

	//int pkcs5PrfCount = LAST_PRF_ID - FIRST_PRF_ID + 1;
	int i,j;

	cryptoInfo=&cryptoInfo_struct;
	memset (cryptoInfo, 0, sizeof (CRYPTO_INFO));
	if (cryptoInfo == NULL)
		return ERR_OUT_OF_MEMORY;


	// Support only XTS
	cryptoInfo->mode= XTS ;

	// Parse Encryption Algorithms		
	cryptoInfo->ea=0;
	if (CORE_encryptionAlgorithm==AES)
		cryptoInfo->ea=1;
	if (CORE_encryptionAlgorithm==SERPENT)
		cryptoInfo->ea=2;
	if (CORE_encryptionAlgorithm==TWOFISH)
		cryptoInfo->ea=3;
	if (CORE_encryptionAlgorithm==TWOFISH_AES)
		cryptoInfo->ea=4;
	if (CORE_encryptionAlgorithm==SERPENT_TWOFISH_AES)
		cryptoInfo->ea=5;
	if (CORE_encryptionAlgorithm==AES_SERPENT)
		cryptoInfo->ea=6;
	if (CORE_encryptionAlgorithm==AES_TWOFISH_SERPENT)
		cryptoInfo->ea=7;
	if (CORE_encryptionAlgorithm==SERPENT_TWOFISH)
		cryptoInfo->ea=8;
/*
	printf("cryptoInfo->ea: %d\n",cryptoInfo->ea);
	printf("EAGetKeySize: %d\n",EAGetKeySize(cryptoInfo->ea));
*/
	memcpy (cryptoInfo->ks, headerKey , EAGetKeySize (cryptoInfo->ea));
	status = EAInit (cryptoInfo->ea, headerKey + 0, cryptoInfo->ks);
	if (status == ERR_CIPHER_INIT_FAILURE)
		return ERR_CIPHER_INIT;

	// Init objects related to the mode of operation
	//if (cryptoInfo->mode == XTS){
		// Copy the secondary key (if cascade, multiple concatenated)
		memcpy (cryptoInfo->k2, headerKey + EAGetKeySize (cryptoInfo->ea), EAGetKeySize (cryptoInfo->ea));
    	
		// Secondary key schedule
		if (!EAInitMode (cryptoInfo))
		{
			return ERR_MODE_INIT_FAILED;
		}
		// or EAInit (cryptoInfo->ea, cryptoInfo->k2, cryptoInfo->ks2) 
    
/*
	printf("cryptoInfo->ks: "); 
	for (int i=0;i<256;i++)
		printf("%02x",(unsigned short)cryptoInfo->ks[i]);
	printf("\n");
	printf("cryptoInfo->ks2: "); 
	for (int i=0;i<256;i++)
		printf("%02x",(unsigned short)cryptoInfo->ks2[i]);
	printf("\n");
	printf("cryptoInfo->k2: "); 
	for (int i=0;i<256;i++)
		printf("%02x",(unsigned short)cryptoInfo->k2[i]);
	printf("\n");
*/

	// Copy the header for decryption
	memcpy (header, encryptedHeader, 512*sizeof(unsigned char));


	// Try to decrypt header
	DecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);

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

