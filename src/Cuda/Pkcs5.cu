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
#include "Pkcs5.cuh"


/*
__device__ void cuda_Pbkdf2 ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey) {
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
}*/

__device__ void cuda_hmac_ripemd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest)
{
    SupportPkcs5 support;
	SupportPkcs5 *sup=&support;
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
	 and text is the data being protected*/
	 // start out by storing key in pads
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
	 
}
/*
__device__ void cuda_hmac_ripemd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest)
{
    RMD160_CTX context;
    unsigned char k_ipad[65];  //inner padding - key XORd with ipad 
    unsigned char k_opad[65];  //outer padding - key XORd with opad
    unsigned char tk[RIPEMD160_DIGESTSIZE];
    int i;
	
    // If the key is longer than the hash algorithm block size, let key = ripemd160(key), as per HMAC specifications. 
    if (keylen > RIPEMD160_BLOCKSIZE)
	{
        RMD160_CTX      tctx;
		
        RMD160Init(&tctx);
        RMD160Update(&tctx, (const unsigned char *) key, keylen);
        RMD160Final(tk, &tctx);
		
        key = ( unsigned char *) tk;
        keylen = RIPEMD160_DIGESTSIZE;
		
		burn (&tctx, sizeof(tctx));	// Prevent leaks
    }
	
	/*
	 
	 RMD160(K XOR opad, RMD160(K XOR ipad, text))
	 
	 where K is an n byte key
	 ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	 opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	 and text is the data being protected 
	
	
	// start out by storing key in pads
	memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
	
    // XOR key with ipad and opad values
    for (i=0; i<keylen; i++)
	{
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }
	
    //perform inner RIPEMD-160
	
    RMD160Init(&context);           // init context for 1st pass
    RMD160Update(&context, k_ipad, RIPEMD160_BLOCKSIZE);  // start with inner pad
    RMD160Update(&context, (const unsigned char *) input, len); // then text of datagram
    RMD160Final((unsigned char *) digest, &context);         // finish up 1st pass
	
    // perform outer RIPEMD-160
    RMD160Init(&context);           // init context for 2nd pass
    RMD160Update(&context, k_opad, RIPEMD160_BLOCKSIZE);  // start with outer pad 
    // results of 1st hash
    RMD160Update(&context, (const unsigned char *) digest, RIPEMD160_DIGESTSIZE);
    RMD160Final((unsigned char *) digest, &context);         // finish up 2nd pass
	
	// Prevent possible leaks. 
    burn (k_ipad, sizeof(k_ipad));
    burn (k_opad, sizeof(k_opad));
	burn (tk, sizeof(tk));
	burn (&context, sizeof(context));
}
*/

__device__ void cuda_derive_u_ripemd160 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b)
{
	unsigned char j[RIPEMD160_DIGESTSIZE], k[RIPEMD160_DIGESTSIZE];
	unsigned char init[128];
	unsigned char counter[4];
	int c, i;
	
	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	cuda_hmac_ripemd160 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, RIPEMD160_DIGESTSIZE);
	
	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		cuda_hmac_ripemd160 (pwd, pwd_len, j, RIPEMD160_DIGESTSIZE, k);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}
	
	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}


__device__ void cuda_derive_key_ripemd160 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen)
{
	unsigned char u[RIPEMD160_DIGESTSIZE];
	int b, l, r;
	
	if (dklen % RIPEMD160_DIGESTSIZE)
	{
		l = 1 + dklen / RIPEMD160_DIGESTSIZE;
	}
	else
	{
		l = dklen / RIPEMD160_DIGESTSIZE;
	}
	
	r = dklen - (l - 1) * RIPEMD160_DIGESTSIZE;
	
	// first l - 1 blocks 
	for (b = 1; b < l; b++)
	{
		cuda_derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}
	
	// last block
	cuda_derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);
	
	// Prevent possible leaks. 
	burn (u, sizeof(u));
	
}













__device__ void cuda_hmac_truncate
  (
	  unsigned char *d1,		/* data to be truncated */
	  unsigned char *d2,		/* truncated data */
	  int len		/* length in bytes to keep */
)
{
	int i;
	for (i = 0; i < len; i++)
		d2[i] = d1[i];
}






__device__ void cuda_hmac_sha512
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  unsigned char *out,		/* output buffer, at least "t" bytes */
	  int t
)
{
	sha512_ctx ictx, octx;
	unsigned char isha[SHA512_DIGESTSIZE], osha[SHA512_DIGESTSIZE];
	unsigned char key[SHA512_DIGESTSIZE];
	unsigned char buf[SHA512_BLOCKSIZE];
	int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = sha512(key), as per HMAC specifications. */
	if (lk > SHA512_BLOCKSIZE)
	{
		sha512_ctx tctx;

		sha512_begin (&tctx);
		sha512_hash ((unsigned char *) k, lk, &tctx);
		sha512_end ((unsigned char *) key, &tctx);

		k = key;
		lk = SHA512_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Inner Digest ****/

	sha512_begin (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (unsigned char) (k[i] ^ 0x36);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = (unsigned char) 0x36;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, &ictx);
	sha512_hash ((unsigned char *) d, ld, &ictx);

	sha512_end ((unsigned char *) isha, &ictx);

	/**** Outer Digest ****/

	sha512_begin (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (unsigned char) (k[i] ^ 0x5C);
	for (i = lk; i < SHA512_BLOCKSIZE; ++i)
		buf[i] = (unsigned char) 0x5C;

	sha512_hash ((unsigned char *) buf, SHA512_BLOCKSIZE, &octx);
	sha512_hash ((unsigned char *) isha, SHA512_DIGESTSIZE, &octx);

	sha512_end ((unsigned char *) osha, &octx);

	/* truncate and print the results */
	t = t > SHA512_DIGESTSIZE ? SHA512_DIGESTSIZE : t;
	cuda_hmac_truncate (osha, out, t);

	/* Prevent leaks */
	burn (&ictx, sizeof(ictx));
	burn (&octx, sizeof(octx));
	burn (isha, sizeof(isha));
	burn (osha, sizeof(osha));
	burn (buf, sizeof(buf));
	burn (key, sizeof(key));
}


__device__ void cuda_derive_u_sha512 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b)
{
	unsigned char j[SHA512_DIGESTSIZE], k[SHA512_DIGESTSIZE];
	unsigned char init[128];
	unsigned char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	cuda_hmac_sha512 (pwd, pwd_len, init, salt_len + 4, j, SHA512_DIGESTSIZE);
	memcpy (u, j, SHA512_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		cuda_hmac_sha512 (pwd, pwd_len, j, SHA512_DIGESTSIZE, k, SHA512_DIGESTSIZE);
		for (i = 0; i < SHA512_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}


__device__ void cuda_derive_key_sha512 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen)
{
	unsigned char u[SHA512_DIGESTSIZE];
	int b, l, r;

	if (dklen % SHA512_DIGESTSIZE)
	{
		l = 1 + dklen / SHA512_DIGESTSIZE;
	}
	else
	{
		l = dklen / SHA512_DIGESTSIZE;
	}

	r = dklen - (l - 1) * SHA512_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		cuda_derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, SHA512_DIGESTSIZE);
		dk += SHA512_DIGESTSIZE;
	}

	/* last block */
	cuda_derive_u_sha512 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}









__device__ void cuda_hmac_whirlpool
(
	  unsigned char *k,		/* secret key */
	  int lk,		/* length of the key in bytes */
	  unsigned char *d,		/* data */
	  int ld,		/* length of data in bytes */
	  unsigned char *out,	/* output buffer, at least "t" bytes */
	  int t
)
{
	WHIRLPOOL_CTX ictx, octx;
	unsigned char iwhi[WHIRLPOOL_DIGESTSIZE], owhi[WHIRLPOOL_DIGESTSIZE];
	unsigned char key[WHIRLPOOL_DIGESTSIZE];
	unsigned char buf[WHIRLPOOL_BLOCKSIZE];
	int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = whirlpool(key), as per HMAC specifications. */
	if (lk > WHIRLPOOL_BLOCKSIZE)
	{
		WHIRLPOOL_CTX tctx;

		WHIRLPOOL_init (&tctx);
		WHIRLPOOL_add ((unsigned char *) k, lk * 8, &tctx);
		WHIRLPOOL_finalize (&tctx, (unsigned char *) key);

		k = key;
		lk = WHIRLPOOL_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));		// Prevent leaks
	}

	/**** Inner Digest ****/

	WHIRLPOOL_init (&ictx);

	/* Pad the key for inner digest */
	for (i = 0; i < lk; ++i)
		buf[i] = (unsigned char) (k[i] ^ 0x36);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = (unsigned char) 0x36;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &ictx);
	WHIRLPOOL_add ((unsigned char *) d, ld * 8, &ictx);

	WHIRLPOOL_finalize (&ictx, (unsigned char *) iwhi);

	/**** Outer Digest ****/

	WHIRLPOOL_init (&octx);

	for (i = 0; i < lk; ++i)
		buf[i] = (unsigned char) (k[i] ^ 0x5C);
	for (i = lk; i < WHIRLPOOL_BLOCKSIZE; ++i)
		buf[i] = (unsigned char) 0x5C;

	WHIRLPOOL_add ((unsigned char *) buf, WHIRLPOOL_BLOCKSIZE * 8, &octx);
	WHIRLPOOL_add ((unsigned char *) iwhi, WHIRLPOOL_DIGESTSIZE * 8, &octx);

	WHIRLPOOL_finalize (&octx, (unsigned char *) owhi);

	/* truncate and print the results */
	t = t > WHIRLPOOL_DIGESTSIZE ? WHIRLPOOL_DIGESTSIZE : t;
	cuda_hmac_truncate (owhi, out, t);

	/* Prevent possible leaks. */
	burn (&ictx, sizeof(ictx));
	burn (&octx, sizeof(octx));
	burn (owhi, sizeof(owhi));
	burn (iwhi, sizeof(iwhi));
	burn (buf, sizeof(buf));
	burn (key, sizeof(key));
}

__device__ void cuda_derive_u_whirlpool (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b)
{
	unsigned char j[WHIRLPOOL_DIGESTSIZE], k[WHIRLPOOL_DIGESTSIZE];
	unsigned char init[128];
	unsigned char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	cuda_hmac_whirlpool (pwd, pwd_len, init, salt_len + 4, j, WHIRLPOOL_DIGESTSIZE);
	memcpy (u, j, WHIRLPOOL_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		cuda_hmac_whirlpool (pwd, pwd_len, j, WHIRLPOOL_DIGESTSIZE, k, WHIRLPOOL_DIGESTSIZE);
		for (i = 0; i < WHIRLPOOL_DIGESTSIZE; i++)
		{
			u[i] ^= k[i];
			j[i] = k[i];
		}
	}

	/* Prevent possible leaks. */
	burn (j, sizeof(j));
	burn (k, sizeof(k));
}

__device__ void cuda_derive_key_whirlpool (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen)
{
	unsigned char u[WHIRLPOOL_DIGESTSIZE];
	int b, l, r;

	if (dklen % WHIRLPOOL_DIGESTSIZE)
	{
		l = 1 + dklen / WHIRLPOOL_DIGESTSIZE;
	}
	else
	{
		l = dklen / WHIRLPOOL_DIGESTSIZE;
	}

	r = dklen - (l - 1) * WHIRLPOOL_DIGESTSIZE;

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		cuda_derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, WHIRLPOOL_DIGESTSIZE);
		dk += WHIRLPOOL_DIGESTSIZE;
	}

	/* last block */
	cuda_derive_u_whirlpool (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}