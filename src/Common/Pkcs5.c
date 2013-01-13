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
 of this file are Copyright (c) 2003-2009 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#include <memory.h>
#include "Rmd160.h"
#ifndef TC_WINDOWS_BOOT
#endif
#include "Pkcs5.h"
#include "Crypto.h"

void hmac_truncate
  (
	  char *d1,		/* data to be truncated */
	  char *d2,		/* truncated data */
	  int len		/* length in bytes to keep */
)
{
	int i;
	for (i = 0; i < len; i++)
		d2[i] = d1[i];
}


void hmac_ripemd160 (char *key, int keylen, char *input, int len, char *digest)
{
    RMD160_CTX context;
    unsigned char k_ipad[65];  /* inner padding - key XORd with ipad */
    unsigned char k_opad[65];  /* outer padding - key XORd with opad */
    unsigned char tk[RIPEMD160_DIGESTSIZE];
    int i;

    /* If the key is longer than the hash algorithm block size,
	   let key = ripemd160(key), as per HMAC specifications. */
    if (keylen > RIPEMD160_BLOCKSIZE) 
	{
        RMD160_CTX      tctx;

        RMD160Init(&tctx);
        RMD160Update(&tctx, (const unsigned char *) key, keylen);
        RMD160Final(tk, &tctx);

        key = (char *) tk;
        keylen = RIPEMD160_DIGESTSIZE;

		burn (&tctx, sizeof(tctx));	// Prevent leaks
    }

	/*

	RMD160(K XOR opad, RMD160(K XOR ipad, text))

	where K is an n byte key
	ipad is the byte 0x36 repeated RIPEMD160_BLOCKSIZE times
	opad is the byte 0x5c repeated RIPEMD160_BLOCKSIZE times
	and text is the data being protected */


	/* start out by storing key in pads */
	memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));

    /* XOR key with ipad and opad values */
    for (i=0; i<keylen; i++) 
	{
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* perform inner RIPEMD-160 */

    RMD160Init(&context);           /* init context for 1st pass */
    RMD160Update(&context, k_ipad, RIPEMD160_BLOCKSIZE);  /* start with inner pad */
    RMD160Update(&context, (const unsigned char *) input, len); /* then text of datagram */
    RMD160Final((unsigned char *) digest, &context);         /* finish up 1st pass */

    /* perform outer RIPEMD-160 */
    RMD160Init(&context);           /* init context for 2nd pass */
    RMD160Update(&context, k_opad, RIPEMD160_BLOCKSIZE);  /* start with outer pad */
    /* results of 1st hash */
    RMD160Update(&context, (const unsigned char *) digest, RIPEMD160_DIGESTSIZE);
    RMD160Final((unsigned char *) digest, &context);         /* finish up 2nd pass */

	/* Prevent possible leaks. */
    burn (k_ipad, sizeof(k_ipad));
    burn (k_opad, sizeof(k_opad));
	burn (tk, sizeof(tk));
	burn (&context, sizeof(context));
}

void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)
{
	char j[RIPEMD160_DIGESTSIZE], k[RIPEMD160_DIGESTSIZE];
	char init[128];
	char counter[4];
	int c, i;

	/* iteration 1 */
	memset (counter, 0, 4);
	counter[3] = (char) b;
	memcpy (init, salt, salt_len);	/* salt */
	memcpy (&init[salt_len], counter, 4);	/* big-endian block number */
	hmac_ripemd160 (pwd, pwd_len, init, salt_len + 4, j);
	memcpy (u, j, RIPEMD160_DIGESTSIZE);

	/* remaining iterations */
	for (c = 1; c < iterations; c++)
	{
		hmac_ripemd160 (pwd, pwd_len, j, RIPEMD160_DIGESTSIZE, k);
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

void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen)
{
	char u[RIPEMD160_DIGESTSIZE];
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

	/* first l - 1 blocks */
	for (b = 1; b < l; b++)
	{
		derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
		memcpy (dk, u, RIPEMD160_DIGESTSIZE);
		dk += RIPEMD160_DIGESTSIZE;
	}

	/* last block */
	derive_u_ripemd160 (pwd, pwd_len, salt, salt_len, iterations, u, b);
	memcpy (dk, u, r);


	/* Prevent possible leaks. */
	burn (u, sizeof(u));
}



char *get_pkcs5_prf_name (int pkcs5_prf_id)
{
	switch (pkcs5_prf_id)
	{

	case RIPEMD160:	
		return "HMAC-RIPEMD-160";


	default:		
		return "(Unknown)";
	}
}



int get_pkcs5_iteration_count (int pkcs5_prf_id, BOOL bBoot)
{
	switch (pkcs5_prf_id)
	{
	case RIPEMD160:	
		return (bBoot ? 1000 : 2000);


	default:		
		TC_THROW_FATAL_EXCEPTION;	// Unknown/wrong ID
	}
	return 0;
}
