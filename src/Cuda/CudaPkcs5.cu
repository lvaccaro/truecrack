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
#include "CudaPkcs5.cuh"



__device__ void cuda_hmac_ripemd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest, SupportPkcs5 *sup)
{
  
    

    int i;
    // If the key is longer than the hash algorithm block size,
    //	   let key = ripemd160(key), as per HMAC specifications. 
    if (keylen > RIPEMD160_BLOCKSIZE) 
	{
	  //RMD160Init(&tctx);
        //RMD160Update(&tctx, (const unsigned char *) key, keylen);
        //RMD160Final(tk, &tctx);
	cuda_RMD160(&sup->ctctx,(unsigned char *) key, keylen,(unsigned char *)NULL,0,sup->ctk);
    
        key = (unsigned char *) sup->ctk;
        keylen = RIPEMD160_DIGESTSIZE;

	//burn (&ctctx, sizeof(ctctx));	// Prevent leaks
    }

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


    /* start out by storing key in pads */
    // XOR key with ipad and opad values 

    for (i=0; i<sizeof(sup->cpad); i++) 
	sup->cpad[i]=0x36;
    for (i=0; i<keylen; i++)
        sup->cpad[i] ^= key[i];
   
    cuda_RMD160(&sup->ccontext,sup->cpad,RIPEMD160_BLOCKSIZE,(const unsigned char *) input, len, (unsigned char *) digest);
   
    for (i=0; i<sizeof(sup->cpad); i++) 
	sup->cpad[i]=0x5c; 
    for (i=0; i<keylen; i++) 
	sup->cpad[i] ^= key[i];
    cuda_RMD160(&sup->ccontext,sup->cpad,RIPEMD160_BLOCKSIZE,(const unsigned char *) digest, RIPEMD160_DIGESTSIZE, (unsigned char *) digest);
   

    // perform inner RIPEMD-160

    //RMD160Init(&context);           // init context for 1st pass
    //RMD160Update(&context, k_ipad, RIPEMD160_BLOCKSIZE);  // start with inner pad
    //RMD160Update(&context, (const unsigned char *) input, len); // then text of datagram 
    //RMD160Final((unsigned char *) digest, &context);         // finish up 1st pass 
    //cuda_RMD160(&ccontext,ck_ipad,RIPEMD160_BLOCKSIZE,(const unsigned char *) input, len, (unsigned char *) digest);
   
    // perform outer RIPEMD-160 
    //RMD160Init(&context);           // init context for 2nd pass 
    //RMD160Update(&context, k_opad, RIPEMD160_BLOCKSIZE);  // start with outer pad 
    // results of 1st hash 
    //RMD160Update(&context, (const unsigned char *) digest, RIPEMD160_DIGESTSIZE);
    //RMD160Final((unsigned char *) digest, &context);         // finish up 2nd pass 
    //cuda_RMD160(&ccontext,ck_opad,RIPEMD160_BLOCKSIZE,(const unsigned char *) digest, RIPEMD160_DIGESTSIZE, (unsigned char *) digest);
   
	// Prevent possible leaks. 
	//burn (ck_ipad, sizeof(ck_ipad));
	//burn (ck_opad, sizeof(ck_opad));
	//burn (ctk, sizeof(ctk));
	//burn (&ccontext, sizeof(ccontext));
}


__device__ void cuda_Pbkdf2 ( unsigned char *salt, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, unsigned char *headerkey, int numData, int numBlock) {
	SupportPkcs5 support;
	SupportPkcs5 *sup;
	sup = &support;
	
	//INCLUDE: void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
	unsigned char *pwd;
	int pwd_len;
	int c, i;
		
	pwd=blockPwd+blockPwd_init[numData];
	pwd_len = blockPwd_length[numData];
	
	
	int b=numBlock;
	unsigned char *u=headerkey+RIPEMD160_DIGESTSIZE*b;

	// iteration 1 
	memset (sup->ccounter, 0, 4);
	sup->ccounter[3] = (char) b+1;
	memcpy (sup->cinit, salt, SALT_LENGTH);	// salt 
	memcpy (&sup->cinit[SALT_LENGTH],sup->ccounter, 4);	// big-endian block number 
	
	cuda_hmac_ripemd160 (pwd, pwd_len, sup->cinit, SALT_LENGTH + 4, sup->cj, sup);
	memcpy (u, sup->cj, RIPEMD160_DIGESTSIZE);
	
	//remaining iterations 
	for (c = 1; c < ITERATIONS; c++)
	{
		cuda_hmac_ripemd160 (pwd, pwd_len, sup->cj, RIPEMD160_DIGESTSIZE, sup->ck,sup);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= sup->ck[i];
			sup->cj[i] = sup->ck[i];
		}
	}
  
}

/*
__device__ void cuda_Pbkdf2 ( unsigned char *salt, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, unsigned char *headerkey, int numData) {
	SupportPkcs5 support;
	SupportPkcs5 *sup;
	sup = &support;
	int numBlock=0;
	unsigned char *pwd;
	int pwd_len;
	int c, i;
		
	pwd=blockPwd+blockPwd_init[numData];
	pwd_len = blockPwd_length[numData];
	
	for(numBlock=0;numBlock<10;numBlock++){
		//  cuda_Pbkdf2 (salt, blockPwd, blockPwd_init, blockPwd_length, headerkey, numData, i);
		
		//INCLUDE: void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)		
		int b=numBlock;
		unsigned char *u=headerkey+RIPEMD160_DIGESTSIZE*b;

		// iteration 1 
		memset (sup->ccounter, 0, 4);
		sup->ccounter[3] = (char) b+1;
		memcpy (sup->cinit, salt, SALT_LENGTH);	// salt 
		memcpy (&sup->cinit[SALT_LENGTH],sup->ccounter, 4);	// big-endian block number 
		
		cuda_hmac_ripemd160 (pwd, pwd_len, sup->cinit, SALT_LENGTH + 4, sup->cj, sup);
		memcpy (u, sup->cj, RIPEMD160_DIGESTSIZE);
		
		//remaining iterations 
		for (c = 1; c < ITERATIONS; c++)
		{
			cuda_hmac_ripemd160 (pwd, pwd_len, sup->cj, RIPEMD160_DIGESTSIZE, sup->ck,sup);
			for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
			{
				u[i] ^= sup->ck[i];
				sup->cj[i] = sup->ck[i];
			}
		}
	}
}
*/
__device__ void cuda_Pbkdf2_charset_ ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey) {
	SupportPkcs5 support;
	SupportPkcs5 *sup;
	sup = &support;
	int numBlock=0;
	int c, i;

	for(numBlock=0;numBlock<10;numBlock++){
		//  cuda_Pbkdf2 (salt, blockPwd, blockPwd_init, blockPwd_length, headerkey, numData, i);
		
		//INCLUDE: void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)		
		int b=numBlock;
		unsigned char *u=headerkey+RIPEMD160_DIGESTSIZE*b;

		// iteration 1 
		memset (sup->ccounter, 0, 4);
		sup->ccounter[3] = (char) b+1;
		memcpy (sup->cinit, salt, SALT_LENGTH);	// salt 
		memcpy (&sup->cinit[SALT_LENGTH],sup->ccounter, 4);	// big-endian block number 
		
		cuda_hmac_ripemd160 (pwd, pwd_len, sup->cinit, SALT_LENGTH + 4, sup->cj, sup);
		memcpy (u, sup->cj, RIPEMD160_DIGESTSIZE);
		
		//remaining iterations 
		for (c = 1; c < ITERATIONS; c++)
		{
			cuda_hmac_ripemd160 (pwd, pwd_len, sup->cj, RIPEMD160_DIGESTSIZE, sup->ck,sup);
			for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
			{
				u[i] ^= sup->ck[i];
				sup->cj[i] = sup->ck[i];
			}
		}
	}
}