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
#if BYTE_ORDER == BIG_ENDIAN
#error The TC_NO_COMPILER_INT64 version of the XTS code is not compatible with big-endian platforms
#endif
#include "Endian.h"

#if BYTE_ORDER == LITTLE_ENDIAN
#	define CUDA_BE16(x) cuda_MirrorBytes16(x)
#	define CUDA_BE32(x) cuda_MirrorBytes32(x)
#	define CUDA_BE64(x) cuda_MirrorBytes64(x)
#else
#	define CUDA_BE16(x) (x)
#	define CUDA_BE32(x) (x)
#	define CUDA_BE64(x) (x)
#endif

__device__ unsigned __int16 cuda_MirrorBytes16 (unsigned __int16 x)
{
	return (x << 8) | (x >> 8);
}


__device__ unsigned __int32 cuda_MirrorBytes32 (unsigned __int32 x)
{
	unsigned __int32 n = (unsigned __int8) x;
	n <<= 8; n |= (unsigned __int8) (x >> 8);
	n <<= 8; n |= (unsigned __int8) (x >> 16);
	return (n << 8) | (unsigned __int8) (x >> 24);
}

#define GetHeaderField16(header,offset) (CUDA_BE16(*(uint16*)(header+offset)))
#define GetHeaderField32(header,offset) (CUDA_BE32(*(uint32*)(header+offset)))

/* CRC polynomial 0x04c11db7 */
__constant__ unsigned __int32 cuda_crc_32_tab[]=
{
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
	0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
	0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
	0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
	0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
	0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
	0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
	0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
	0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
	0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
	0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
	0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
	0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
	0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
	0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
	0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
	0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
	0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
	0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
	0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
	0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
	0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
	0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
	0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
	0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
	0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

__device__ unsigned __int32 cuGetCrc32 (unsigned char *data, int length)
{
	unsigned __int32 CRC = 0xffffffff;
	
	while (length--)
	{
		CRC = (CRC >> 8) ^ cuda_crc_32_tab[ (CRC ^ *data++) & 0xFF ];
	}
	
	return CRC ^ 0xffffffff;
}

__device__ void cuda_memcpy (unsigned char* to , unsigned char* from, int length){
	int i;
	for (i=0;i<length;i++)
		to[i]=from[i];
}




// Encrypts or decrypts all blocks in the buffer in XTS mode. For descriptions of the input parameters,
// see the 64-bit version of EncryptBufferXTS().
__device__ static void cuEncryptDecryptBufferXTS32 (const unsigned __int8 *buffer,
													   TC_LARGEST_COMPILER_UINT length,
													   const UINT64_STRUCT *startDataUnitNo,
													   unsigned int startBlock,
													   unsigned __int8 *ks,
													   unsigned __int8 *ks2,
													   int cipher,
													   BOOL decryption)
{
	
	__align__(8) unsigned __int8 byteBufUnitNo [BYTES_PER_XTS_BLOCK];
	__align__(8) unsigned __int8 whiteningValue [BYTES_PER_XTS_BLOCK];
	__align__(8) unsigned __int8 finalCarry;
	unsigned __int32 *whiteningValuePtr32;
	unsigned __int32 *finalDwordWhiteningValuePtr;
	unsigned __int32 *bufPtr32;
	
	TC_LARGEST_COMPILER_UINT blockCount;
	UINT64_STRUCT dataUnitNo;
	unsigned int block;
	unsigned int endBlock;
	
	
	bufPtr32 = (unsigned __int32 *) buffer;
	whiteningValuePtr32 = (unsigned __int32 *) whiteningValue;
	finalDwordWhiteningValuePtr = whiteningValuePtr32 + sizeof (whiteningValue) / sizeof (*whiteningValuePtr32) - 1;
	
	
	// Store the 64-bit data unit number in a way compatible with non-64-bit environments/platforms
	dataUnitNo.HighPart = startDataUnitNo->HighPart;
	dataUnitNo.LowPart = startDataUnitNo->LowPart;
	
	blockCount = length / BYTES_PER_XTS_BLOCK;
	
	// Convert the 64-bit data unit number into a little-endian 16-byte array.
	// (Passed as two 32-bit integers for compatibility with non-64-bit environments/platforms.)
	cuUint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
	
	// Generate whitening values for all blocks in the buffer
	while (blockCount > 0)
	{
		
		
		if (blockCount < BLOCKS_PER_XTS_DATA_UNIT)
			endBlock = startBlock + (unsigned int) blockCount;
		else
			endBlock = BLOCKS_PER_XTS_DATA_UNIT;
		
		
		// Encrypt the data unit number using the secondary key (in order to generate the first
		// whitening value for this data unit)
		cuUint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
		cuda_memcpy (whiteningValue, byteBufUnitNo, BYTES_PER_XTS_BLOCK);
		cuEncipherBlock (cipher, whiteningValue, ks2);
		
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
					cuDecipherBlock (cipher, bufPtr32, ks);
				else
					cuEncipherBlock (cipher, bufPtr32, ks);
				
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
		cuUint64ToLE16ByteArray (byteBufUnitNo, dataUnitNo.HighPart, dataUnitNo.LowPart);
	}
	
	FAST_ERASE64 (whiteningValue, sizeof (whiteningValue));
}


// For descriptions of the input parameters, see the 64-bit version of EncryptBufferXTS().
__device__ void cuDecryptBufferXTS (unsigned __int8 *buffer,
									   TC_LARGEST_COMPILER_UINT length,
									   const UINT64_STRUCT *startDataUnitNo,
									   unsigned int startCipherBlockNo,
									   unsigned __int8 *ks,
									   unsigned __int8 *ks2,
									   int cipher)
{
	// Decrypt all ciphertext blocks in the buffer
	cuEncryptDecryptBufferXTS32 (buffer, length, startDataUnitNo, startCipherBlockNo, ks, ks2, cipher, TRUE);
}

__device__ void cuDecryptBuffer (unsigned __int8 *buf, TC_LARGEST_COMPILER_UINT len, PCRYPTO_INFO cryptoInfo)
{
	//unsigned __int8 *ks = cryptoInfo->ks;  //+ EAGetKeyScheduleSize (cryptoInfo->ea);
	//unsigned __int8 *ks2 = cryptoInfo->ks2;// + EAGetKeyScheduleSize (cryptoInfo->ea);
	UINT64_STRUCT dataUnitNo;
	//int cipher;
	
	// When encrypting/decrypting a buffer (typically a volume header) the sequential number
	// of the first XTS data unit in the buffer is always 0 and the start of the buffer is
	// always assumed to be aligned with the start of the data unit 0.
	dataUnitNo.LowPart = 0;
	dataUnitNo.HighPart = 0;
	
	//	for (cipher = EAGetLastCipher (cryptoInfo->ea);
	//		cipher != 0;
	//		cipher = EAGetPreviousCipher (cryptoInfo->ea, cipher))
	//	{
	//		ks -= CipherGetKeyScheduleSize (cipher);
	//		ks2 -= CipherGetKeyScheduleSize (cipher);
	cuDecryptBufferXTS (buf, len, &dataUnitNo, 0, cryptoInfo->ks, cryptoInfo->ks2, cryptoInfo->ea);
	//	}
}



__device__ int cuXts(int encryptionAlgorithm, unsigned char *encryptedHeader, unsigned char *headerKey, unsigned char *header) {
	
    PCRYPTO_INFO cryptoInfo;
    CRYPTO_INFO cryptoInfo_struct;
	
    uint16 headerVersion;
    int status = ERR_PARAMETER_INCORRECT;
    int primaryKeyOffset=0;
	int eaGetKeySize=32; 
	
    //int pkcs5PrfCount = LAST_PRF_ID - FIRST_PRF_ID + 1;
	
    cryptoInfo=&cryptoInfo_struct;    
    if (cryptoInfo == NULL)
        return ERR_OUT_OF_MEMORY;
    memset (cryptoInfo, 0, sizeof (CRYPTO_INFO));

    // Init objects related to the mode of operation
	// Support only XTS
    cryptoInfo->mode= XTS ;
	if (encryptionAlgorithm!=AES && encryptionAlgorithm!=SERPENT && encryptionAlgorithm!=TWOFISH)
		return UNDEFINED;
    cryptoInfo->ea=encryptionAlgorithm;
	
	// Primary key schedule
	cuda_memcpy (cryptoInfo->k2, headerKey + primaryKeyOffset, 64);
	status = cuCipherInit (cryptoInfo->ea, cryptoInfo->k2, cryptoInfo->ks);
    if (status != ERR_SUCCESS)
        return ERR_CIPHER_INIT;
        
    // Secondary key schedule
    cuda_memcpy (cryptoInfo->k2, headerKey + eaGetKeySize, eaGetKeySize);
	status = cuCipherInit (cryptoInfo->ea, cryptoInfo->k2, cryptoInfo->ks2);
    if (status != ERR_SUCCESS)
        return ERR_MODE_INIT;
    
 
    // Copy the header for decryption
    cuda_memcpy (header, encryptedHeader, 512*sizeof(unsigned char));
	
    // Try to decrypt header
    cuDecryptBuffer (header + HEADER_ENCRYPTED_DATA_OFFSET, HEADER_ENCRYPTED_DATA_SIZE, cryptoInfo);
	    
	// Magic 'TRUE'
	if (GetHeaderField32 (header, TC_HEADER_OFFSET_MAGIC) != 0x54525545)
		return ERR_MAGIC_TRUE;
	
	// Header version
	headerVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_VERSION);
	if (headerVersion > VOLUME_HEADER_VERSION) {
		return ERR_VERSION_REQUIRED;
	}
	
	// Check CRC of the header fields
	if (headerVersion >= 4
		&& GetHeaderField32 (header, TC_HEADER_OFFSET_HEADER_CRC) != cuGetCrc32 (header + TC_HEADER_OFFSET_MAGIC, TC_HEADER_OFFSET_HEADER_CRC - TC_HEADER_OFFSET_MAGIC))
		//printf("Unsuccessful\n");
		return ERR_CRC_HEADER_FIELDS;
	// Required program version
	//cryptoInfo->RequiredProgramVersion = GetHeaderField16 (header, TC_HEADER_OFFSET_REQUIRED_VERSION);
	//cryptoInfo->LegacyVolume = cryptoInfo->RequiredProgramVersion < 0x600;
	
	// Check CRC of the key set
	if (GetHeaderField32 (header, TC_HEADER_OFFSET_KEY_AREA_CRC) != cuGetCrc32 (header + HEADER_MASTER_KEYDATA_OFFSET, MASTER_KEYDATA_SIZE))
		return ERR_CRC_KEY_SET;

    return SUCCESS;
}



