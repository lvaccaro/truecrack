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

#ifndef TC_HEADER_Crypto_CUDARIPEMD160
#define TC_HEADER_Crypto_CUDARIPEMD160

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define RIPEMD160_BLOCK_LENGTH 64

typedef struct RMD160Context
{
	unsigned __int32 state[5];
#ifndef TC_WINDOWS_BOOT
	uint64 count;
#else
	uint16 count;
#endif
	unsigned char buffer[RIPEMD160_BLOCK_LENGTH];
} RMD160_CTX;


__device__ void RMD160Init (RMD160_CTX *ctx);
__device__ void RMD160Transform (unsigned __int32 *state, const unsigned __int32 *data);
__device__ void RMD160Update (RMD160_CTX *ctx, const unsigned char *input, unsigned __int32 len);
__device__ void RMD160Final (unsigned char *digest, RMD160_CTX *ctx);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_CUDARIPEMD160
