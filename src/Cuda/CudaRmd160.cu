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
// RIPEMD-160 written and placed in the public domain by Wei Dai

/*
 * This code implements the MD4 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 */

/* Adapted for TrueCrypt */

#include <memory.h>
#include "Tcdefs.h"
#include "Endian.h"
#include "CudaRmd160.cuh"

#define F(x, y, z)    (x ^ y ^ z) 
#define G(x, y, z)    (z ^ (x & (y^z)))
#define H(x, y, z)    (z ^ (x | ~y))
#define I(x, y, z)    (y ^ (z & (x^y)))
#define J(x, y, z)    (x ^ (y | ~z))

#define PUT_64BIT_LE(cp, value) do {                                    \
	(cp)[7] = (byte) ((value) >> 56);                                        \
	(cp)[6] = (byte) ((value) >> 48);                                        \
	(cp)[5] = (byte) ((value) >> 40);                                        \
	(cp)[4] = (byte) ((value) >> 32);                                        \
	(cp)[3] = (byte) ((value) >> 24);                                        \
	(cp)[2] = (byte) ((value) >> 16);                                        \
	(cp)[1] = (byte) ((value) >> 8);                                         \
	(cp)[0] = (byte) (value); } while (0)

#define PUT_32BIT_LE(cp, value) do {                                    \
	(cp)[3] = (byte) ((value) >> 24);                                        \
	(cp)[2] = (byte) ((value) >> 16);                                        \
	(cp)[1] = (byte) ((value) >> 8);                                         \
	(cp)[0] = (byte) (value); } while (0)

#define word32 unsigned __int32

#define k0 0
#define k1 0x5a827999UL
#define k2 0x6ed9eba1UL
#define k3 0x8f1bbcdcUL
#define k4 0xa953fd4eUL
#define k5 0x50a28be6UL
#define k6 0x5c4dd124UL
#define k7 0x6d703ef3UL
#define k8 0x7a6d76e9UL
#define k9 0

#define  rotlFixed( x, y) (word32)((x<<y) | (x>>(sizeof(word32)*8-y)))
  
//__device__ word32 rotlFixed (word32 x, unsigned int y)
//{ 
//	return (word32)((x<<y) | (x>>(sizeof(word32)*8-y)));
//}

#define Subround(f, a, b, c, d, e, x, s, k)        \
	a += f(b, c, d) + x + k;\
	a = rotlFixed((word32)a, s) + e;\
	c = rotlFixed((word32)c, 10U)


/*
static byte PADDING[64]= {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
*/

__device__ void cuda_RMD160 (RMD160_CTX *ctx, const unsigned char *input1, unsigned __int32 lenArg1, const unsigned char *input2, unsigned __int32 lenArg2, unsigned char *digest){
	//global variable of the subset of functions
	uint32 padlen;
	byte count[8];
	byte PADDING[64];
	unsigned int update2_flags;
	
	if (input2==NULL || lenArg2==0)
	  update2_flags=FALSE;
	else
	  update2_flags=TRUE;
	
	// INCLUDE: void RMD160Init (RMD160_CTX *ctx)
	{
	int i;
	ctx->count = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xc3d2e1f0;

	for (i=0;i<64;i++)
		PADDING[i]=0;
	PADDING[0] = 0x80;
	}
	// ENDINCLUDE: void RMD160Init (RMD160_CTX *ctx)
	
	
	// INCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input1, unsigned __int32 lenArg1)
	{
#ifndef TC_WINDOWS_BOOT
	uint32 len = lenArg1, have, need;
#else
	uint16 len = (uint16) lenArg1, have, need;
#endif
	/* Check how many bytes we already have and how many more we need. */
	have = ((ctx->count >> 3) & (RIPEMD160_BLOCK_LENGTH - 1));
	need = RIPEMD160_BLOCK_LENGTH - have;
	/* Update bitcount */
	ctx->count += len << 3;
	if (len >= need) {
		if (have != 0) {
			memcpy (ctx->buffer + have, input1, (size_t) need);
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) ctx->buffer);
			input1 += need;
			len -= need;
			have = 0;
		}
		// Process data in RIPEMD160_BLOCK_LENGTH-byte chunks. 
		while (len >= RIPEMD160_BLOCK_LENGTH) {
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) input1);
			input1 += RIPEMD160_BLOCK_LENGTH;
			len -= RIPEMD160_BLOCK_LENGTH;
		}	  
	}
	/* Handle any remaining bytes of data. */
	if (len != 0)
		memcpy (ctx->buffer + have, input1, (size_t) len);
	}
	// ENDINCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input1, unsigned __int32 lenArg1)
	
	if (update2_flags==TRUE)
	// INCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input2, unsigned __int32 lenArg2)
	{
#ifndef TC_WINDOWS_BOOT
	uint32 len = lenArg2, have, need;
#else
	uint16 len = (uint16) lenArg2, have, need;
#endif
	/* Check how many bytes we already have and how many more we need. */
	have = ((ctx->count >> 3) & (RIPEMD160_BLOCK_LENGTH - 1));
	need = RIPEMD160_BLOCK_LENGTH - have;
	/* Update bitcount */
	ctx->count += len << 3;
	if (len >= need) {
		if (have != 0) {
			memcpy (ctx->buffer + have, input2, (size_t) need);
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) ctx->buffer);
			input2 += need;
			len -= need;
			have = 0;
		}
		// Process data in RIPEMD160_BLOCK_LENGTH-byte chunks. 
		while (len >= RIPEMD160_BLOCK_LENGTH) {
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) input2);
			input2 += RIPEMD160_BLOCK_LENGTH;
			len -= RIPEMD160_BLOCK_LENGTH;
		}	  
	}
	/* Handle any remaining bytes of data. */
	if (len != 0)
		memcpy (ctx->buffer + have, input2, (size_t) len);
	}// ENDINCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input2, unsigned __int32 lenArg2)
	
	
	// INCLUDE: void RMD160Pad(RMD160_CTX *ctx)
	{
	/* Convert count to 8 bytes in little endian order. */
#ifndef TC_WINDOWS_BOOT
	PUT_64BIT_LE(count, ctx->count);
#else
	*(uint32 *) (count + 4) = 0;
	*(uint16 *) (count + 2) = 0;
	*(uint16 *) (count + 0) = ctx->count;
#endif
	/* Pad out to 56 mod 64. */
	padlen = RIPEMD160_BLOCK_LENGTH -
		(uint32)((ctx->count >> 3) & (RIPEMD160_BLOCK_LENGTH - 1));
	if (padlen < 1 + 8)
		padlen += RIPEMD160_BLOCK_LENGTH;
	}
	// ENDINCLUDE: void RMD160Pad(RMD160_CTX *ctx)
	
		
	
	
	// INCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input3, unsigned __int32 lenArg3) 
	// Call RMD160Update(ctx, PADDING, padlen - 8);
	{
	  unsigned char *input3;
	  input3=(unsigned char *)PADDING;
	  unsigned __int32 lenArg3=padlen-8;
#ifndef TC_WINDOWS_BOOT
	uint32 len = lenArg3, have, need;
#else
	uint16 len = (uint16) lenArg3, have, need;
#endif
	/* Check how many bytes we already have and how many more we need. */
	have = ((ctx->count >> 3) & (RIPEMD160_BLOCK_LENGTH - 1));
	need = RIPEMD160_BLOCK_LENGTH - have;
	/* Update bitcount */
	ctx->count += len << 3;
	if (len >= need) {
		if (have != 0) {
			memcpy (ctx->buffer + have, input3, (size_t) need);
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) ctx->buffer);
			input3 += need;
			len -= need;
			have = 0;
		}
		// Process data in RIPEMD160_BLOCK_LENGTH-byte chunks. 
		while (len >= RIPEMD160_BLOCK_LENGTH) {
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) input3);
			input3 += RIPEMD160_BLOCK_LENGTH;
			len -= RIPEMD160_BLOCK_LENGTH;
		}	  
	}
	/* Handle any remaining bytes of data. */
	if (len != 0)
		memcpy (ctx->buffer + have, input3, (size_t) len);
	}// ENDINCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input3, unsigned __int32 lenArg3)
	

	
	// INCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input4, unsigned __int32 lenArg4) 
	// Call RMD160Update(ctx, count, 8);
	{
	  unsigned char *input4;
	  input4=(unsigned char *)count;
	  unsigned __int32 lenArg4=8;
#ifndef TC_WINDOWS_BOOT
	uint32 len = lenArg4, have, need;
#else
	uint16 len = (uint16) lenArg4, have, need;
#endif
	/* Check how many bytes we already have and how many more we need. */
	have = ((ctx->count >> 3) & (RIPEMD160_BLOCK_LENGTH - 1));
	need = RIPEMD160_BLOCK_LENGTH - have;
	/* Update bitcount */
	ctx->count += len << 3;
	if (len >= need) {
		if (have != 0) {
			memcpy (ctx->buffer + have, input4, (size_t) need);
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) ctx->buffer);
			input4 += need;
			len -= need;
			have = 0;
		}
		// Process data in RIPEMD160_BLOCK_LENGTH-byte chunks. 
		while (len >= RIPEMD160_BLOCK_LENGTH) {
			cuda_RMD160Transform ((uint32 *) ctx->state, (const uint32 *) input4);
			input4 += RIPEMD160_BLOCK_LENGTH;
			len -= RIPEMD160_BLOCK_LENGTH;
		}	  
	}
	/* Handle any remaining bytes of data. */
	if (len != 0)
		memcpy (ctx->buffer + have, input4, (size_t) len);
	}// ENDINCLUDE: void RMD160Update (RMD160_CTX *ctx, const unsigned char *input4, unsigned __int32 lenArg4) 
		
		
		
	
	// INCLUDE: RMD160Final(unsigned char *digest, RMD160_CTX *ctx)	
	int i;
	if (digest) {
		for (i = 0; i < 5; i++)
			PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
		memset (ctx, 0, sizeof(*ctx));
	}	
	// ENDINCLUDE: RMD160Final(unsigned char *digest, RMD160_CTX *ctx)
}



__device__ void cuda_RMD160Transform (unsigned __int32 *digest, const unsigned __int32 *data)
{
 
#if BYTE_ORDER == LITTLE_ENDIAN
	const unsigned __int32 *X = data;
#else
	unsigned __int32 X[16];
	int i;
#endif

	unsigned __int32 a1, b1, c1, d1, e1, a2, b2, c2, d2, e2;
	
	a1 = a2 = digest[0];
	b1 = b2 = digest[1];
	c1 = c2 = digest[2];
	d1 = d2 = digest[3];
	e1 = e2 = digest[4];
	

#if BYTE_ORDER == BIG_ENDIAN
	for (i = 0; i < 16; i++)
	{
		X[i] = LE32 (data[i]);
	}
#endif

	Subround(F, a1, b1, c1, d1, e1, X[ 0], 11, k0);
	Subround(F, e1, a1, b1, c1, d1, X[ 1], 14, k0);
	Subround(F, d1, e1, a1, b1, c1, X[ 2], 15, k0);
	Subround(F, c1, d1, e1, a1, b1, X[ 3], 12, k0);
	Subround(F, b1, c1, d1, e1, a1, X[ 4],  5, k0);
	Subround(F, a1, b1, c1, d1, e1, X[ 5],  8, k0);
	Subround(F, e1, a1, b1, c1, d1, X[ 6],  7, k0);
	Subround(F, d1, e1, a1, b1, c1, X[ 7],  9, k0);
	Subround(F, c1, d1, e1, a1, b1, X[ 8], 11, k0);
	Subround(F, b1, c1, d1, e1, a1, X[ 9], 13, k0);
	Subround(F, a1, b1, c1, d1, e1, X[10], 14, k0);
	Subround(F, e1, a1, b1, c1, d1, X[11], 15, k0);
	Subround(F, d1, e1, a1, b1, c1, X[12],  6, k0);
	Subround(F, c1, d1, e1, a1, b1, X[13],  7, k0);
	Subround(F, b1, c1, d1, e1, a1, X[14],  9, k0);
	Subround(F, a1, b1, c1, d1, e1, X[15],  8, k0);

	Subround(G, e1, a1, b1, c1, d1, X[ 7],  7, k1);
	Subround(G, d1, e1, a1, b1, c1, X[ 4],  6, k1);
	Subround(G, c1, d1, e1, a1, b1, X[13],  8, k1);
	Subround(G, b1, c1, d1, e1, a1, X[ 1], 13, k1);
	Subround(G, a1, b1, c1, d1, e1, X[10], 11, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 6],  9, k1);
	Subround(G, d1, e1, a1, b1, c1, X[15],  7, k1);
	Subround(G, c1, d1, e1, a1, b1, X[ 3], 15, k1);
	Subround(G, b1, c1, d1, e1, a1, X[12],  7, k1);
	Subround(G, a1, b1, c1, d1, e1, X[ 0], 12, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 9], 15, k1);
	Subround(G, d1, e1, a1, b1, c1, X[ 5],  9, k1);
	Subround(G, c1, d1, e1, a1, b1, X[ 2], 11, k1);
	Subround(G, b1, c1, d1, e1, a1, X[14],  7, k1);
	Subround(G, a1, b1, c1, d1, e1, X[11], 13, k1);
	Subround(G, e1, a1, b1, c1, d1, X[ 8], 12, k1);

	Subround(H, d1, e1, a1, b1, c1, X[ 3], 11, k2);
	Subround(H, c1, d1, e1, a1, b1, X[10], 13, k2);
	Subround(H, b1, c1, d1, e1, a1, X[14],  6, k2);
	Subround(H, a1, b1, c1, d1, e1, X[ 4],  7, k2);
	Subround(H, e1, a1, b1, c1, d1, X[ 9], 14, k2);
	Subround(H, d1, e1, a1, b1, c1, X[15],  9, k2);
	Subround(H, c1, d1, e1, a1, b1, X[ 8], 13, k2);
	Subround(H, b1, c1, d1, e1, a1, X[ 1], 15, k2);
	Subround(H, a1, b1, c1, d1, e1, X[ 2], 14, k2);
	Subround(H, e1, a1, b1, c1, d1, X[ 7],  8, k2);
	Subround(H, d1, e1, a1, b1, c1, X[ 0], 13, k2);
	Subround(H, c1, d1, e1, a1, b1, X[ 6],  6, k2);
	Subround(H, b1, c1, d1, e1, a1, X[13],  5, k2);
	Subround(H, a1, b1, c1, d1, e1, X[11], 12, k2);
	Subround(H, e1, a1, b1, c1, d1, X[ 5],  7, k2);
	Subround(H, d1, e1, a1, b1, c1, X[12],  5, k2);

	Subround(I, c1, d1, e1, a1, b1, X[ 1], 11, k3);
	Subround(I, b1, c1, d1, e1, a1, X[ 9], 12, k3);
	Subround(I, a1, b1, c1, d1, e1, X[11], 14, k3);
	Subround(I, e1, a1, b1, c1, d1, X[10], 15, k3);
	Subround(I, d1, e1, a1, b1, c1, X[ 0], 14, k3);
	Subround(I, c1, d1, e1, a1, b1, X[ 8], 15, k3);
	Subround(I, b1, c1, d1, e1, a1, X[12],  9, k3);
	Subround(I, a1, b1, c1, d1, e1, X[ 4],  8, k3);
	Subround(I, e1, a1, b1, c1, d1, X[13],  9, k3);
	Subround(I, d1, e1, a1, b1, c1, X[ 3], 14, k3);
	Subround(I, c1, d1, e1, a1, b1, X[ 7],  5, k3);
	Subround(I, b1, c1, d1, e1, a1, X[15],  6, k3);
	Subround(I, a1, b1, c1, d1, e1, X[14],  8, k3);
	Subround(I, e1, a1, b1, c1, d1, X[ 5],  6, k3);
	Subround(I, d1, e1, a1, b1, c1, X[ 6],  5, k3);
	Subround(I, c1, d1, e1, a1, b1, X[ 2], 12, k3);

	Subround(J, b1, c1, d1, e1, a1, X[ 4],  9, k4);
	Subround(J, a1, b1, c1, d1, e1, X[ 0], 15, k4);
	Subround(J, e1, a1, b1, c1, d1, X[ 5],  5, k4);
	Subround(J, d1, e1, a1, b1, c1, X[ 9], 11, k4);
	Subround(J, c1, d1, e1, a1, b1, X[ 7],  6, k4);
	Subround(J, b1, c1, d1, e1, a1, X[12],  8, k4);
	Subround(J, a1, b1, c1, d1, e1, X[ 2], 13, k4);
	Subround(J, e1, a1, b1, c1, d1, X[10], 12, k4);
	Subround(J, d1, e1, a1, b1, c1, X[14],  5, k4);
	Subround(J, c1, d1, e1, a1, b1, X[ 1], 12, k4);
	Subround(J, b1, c1, d1, e1, a1, X[ 3], 13, k4);
	Subround(J, a1, b1, c1, d1, e1, X[ 8], 14, k4);
	Subround(J, e1, a1, b1, c1, d1, X[11], 11, k4);
	Subround(J, d1, e1, a1, b1, c1, X[ 6],  8, k4);
	Subround(J, c1, d1, e1, a1, b1, X[15],  5, k4);
	Subround(J, b1, c1, d1, e1, a1, X[13],  6, k4);

	Subround(J, a2, b2, c2, d2, e2, X[ 5],  8, k5);
	Subround(J, e2, a2, b2, c2, d2, X[14],  9, k5);
	Subround(J, d2, e2, a2, b2, c2, X[ 7],  9, k5);
	Subround(J, c2, d2, e2, a2, b2, X[ 0], 11, k5);
	Subround(J, b2, c2, d2, e2, a2, X[ 9], 13, k5);
	Subround(J, a2, b2, c2, d2, e2, X[ 2], 15, k5);
	Subround(J, e2, a2, b2, c2, d2, X[11], 15, k5);
	Subround(J, d2, e2, a2, b2, c2, X[ 4],  5, k5);
	Subround(J, c2, d2, e2, a2, b2, X[13],  7, k5);
	Subround(J, b2, c2, d2, e2, a2, X[ 6],  7, k5);
	Subround(J, a2, b2, c2, d2, e2, X[15],  8, k5);
	Subround(J, e2, a2, b2, c2, d2, X[ 8], 11, k5);
	Subround(J, d2, e2, a2, b2, c2, X[ 1], 14, k5);
	Subround(J, c2, d2, e2, a2, b2, X[10], 14, k5);
	Subround(J, b2, c2, d2, e2, a2, X[ 3], 12, k5);
	Subround(J, a2, b2, c2, d2, e2, X[12],  6, k5);

	Subround(I, e2, a2, b2, c2, d2, X[ 6],  9, k6); 
	Subround(I, d2, e2, a2, b2, c2, X[11], 13, k6);
	Subround(I, c2, d2, e2, a2, b2, X[ 3], 15, k6);
	Subround(I, b2, c2, d2, e2, a2, X[ 7],  7, k6);
	Subround(I, a2, b2, c2, d2, e2, X[ 0], 12, k6);
	Subround(I, e2, a2, b2, c2, d2, X[13],  8, k6);
	Subround(I, d2, e2, a2, b2, c2, X[ 5],  9, k6);
	Subround(I, c2, d2, e2, a2, b2, X[10], 11, k6);
	Subround(I, b2, c2, d2, e2, a2, X[14],  7, k6);
	Subround(I, a2, b2, c2, d2, e2, X[15],  7, k6);
	Subround(I, e2, a2, b2, c2, d2, X[ 8], 12, k6);
	Subround(I, d2, e2, a2, b2, c2, X[12],  7, k6);
	Subround(I, c2, d2, e2, a2, b2, X[ 4],  6, k6);
	Subround(I, b2, c2, d2, e2, a2, X[ 9], 15, k6);
	Subround(I, a2, b2, c2, d2, e2, X[ 1], 13, k6);
	Subround(I, e2, a2, b2, c2, d2, X[ 2], 11, k6);

	Subround(H, d2, e2, a2, b2, c2, X[15],  9, k7);
	Subround(H, c2, d2, e2, a2, b2, X[ 5],  7, k7);
	Subround(H, b2, c2, d2, e2, a2, X[ 1], 15, k7);
	Subround(H, a2, b2, c2, d2, e2, X[ 3], 11, k7);
	Subround(H, e2, a2, b2, c2, d2, X[ 7],  8, k7);
	Subround(H, d2, e2, a2, b2, c2, X[14],  6, k7);
	Subround(H, c2, d2, e2, a2, b2, X[ 6],  6, k7);
	Subround(H, b2, c2, d2, e2, a2, X[ 9], 14, k7);
	Subround(H, a2, b2, c2, d2, e2, X[11], 12, k7);
	Subround(H, e2, a2, b2, c2, d2, X[ 8], 13, k7);
	Subround(H, d2, e2, a2, b2, c2, X[12],  5, k7);
	Subround(H, c2, d2, e2, a2, b2, X[ 2], 14, k7);
	Subround(H, b2, c2, d2, e2, a2, X[10], 13, k7);
	Subround(H, a2, b2, c2, d2, e2, X[ 0], 13, k7);
	Subround(H, e2, a2, b2, c2, d2, X[ 4],  7, k7);
	Subround(H, d2, e2, a2, b2, c2, X[13],  5, k7);

	Subround(G, c2, d2, e2, a2, b2, X[ 8], 15, k8);
	Subround(G, b2, c2, d2, e2, a2, X[ 6],  5, k8);
	Subround(G, a2, b2, c2, d2, e2, X[ 4],  8, k8);
	Subround(G, e2, a2, b2, c2, d2, X[ 1], 11, k8);
	Subround(G, d2, e2, a2, b2, c2, X[ 3], 14, k8);
	Subround(G, c2, d2, e2, a2, b2, X[11], 14, k8);
	Subround(G, b2, c2, d2, e2, a2, X[15],  6, k8);
	Subround(G, a2, b2, c2, d2, e2, X[ 0], 14, k8);
	Subround(G, e2, a2, b2, c2, d2, X[ 5],  6, k8);
	Subround(G, d2, e2, a2, b2, c2, X[12],  9, k8);
	Subround(G, c2, d2, e2, a2, b2, X[ 2], 12, k8);
	Subround(G, b2, c2, d2, e2, a2, X[13],  9, k8);
	Subround(G, a2, b2, c2, d2, e2, X[ 9], 12, k8);
	Subround(G, e2, a2, b2, c2, d2, X[ 7],  5, k8);
	Subround(G, d2, e2, a2, b2, c2, X[10], 15, k8);
	Subround(G, c2, d2, e2, a2, b2, X[14],  8, k8);

	Subround(F, b2, c2, d2, e2, a2, X[12],  8, k9);
	Subround(F, a2, b2, c2, d2, e2, X[15],  5, k9);
	Subround(F, e2, a2, b2, c2, d2, X[10], 12, k9);
	Subround(F, d2, e2, a2, b2, c2, X[ 4],  9, k9);
	Subround(F, c2, d2, e2, a2, b2, X[ 1], 12, k9);
	Subround(F, b2, c2, d2, e2, a2, X[ 5],  5, k9);
	Subround(F, a2, b2, c2, d2, e2, X[ 8], 14, k9);
	Subround(F, e2, a2, b2, c2, d2, X[ 7],  6, k9);
	Subround(F, d2, e2, a2, b2, c2, X[ 6],  8, k9);
	Subround(F, c2, d2, e2, a2, b2, X[ 2], 13, k9);
	Subround(F, b2, c2, d2, e2, a2, X[13],  6, k9);
	Subround(F, a2, b2, c2, d2, e2, X[14],  5, k9);
	Subround(F, e2, a2, b2, c2, d2, X[ 0], 15, k9);
	Subround(F, d2, e2, a2, b2, c2, X[ 3], 13, k9);
	Subround(F, c2, d2, e2, a2, b2, X[ 9], 11, k9);
	Subround(F, b2, c2, d2, e2, a2, X[11], 11, k9);

	c1        = digest[1] + c1 + d2;
	digest[1] = digest[2] + d1 + e2;
	digest[2] = digest[3] + e1 + a2;
	digest[3] = digest[4] + a1 + b2;
	digest[4] = digest[0] + b1 + c2;
	digest[0] = c1;
	
}
