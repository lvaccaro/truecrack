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
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007
*/

/* Adapted for TrueCrypt:
   - Added run-time table generator for Aes_x86_v2.asm
*/

#define DO_TABLES

//#include "Aes.h"
//#include "Aesopt.h"
#include "CudaAes.cuh"

#if defined(FIXED_TABLES)

/* implemented in case of wrong call for fixed tables */

AES_RETURN aes_init(void)
{
    return EXIT_SUCCESS;
}

#else   /* dynamic table generation */

#if !defined(FF_TABLES)

/*  Generate the tables for the dynamic table option

    It will generally be sensible to use tables to compute finite
    field multiplies and inverses but where memory is scarse this
    code might sometimes be better. But it only has effect during
    initialisation so its pretty unimportant in overall terms.
*/

/*  return 2 ^ (n - 1) where n is the bit number of the highest bit
    set in x with x in the range 1 < x < 0x00000200.   This form is
    used so that locals within fi can be bytes rather than words
*/

static uint_8t hibit(const uint_32t x)
{   uint_8t r = (uint_8t)((x >> 1) | (x >> 2));

    r |= (r >> 2);
    r |= (r >> 4);
    return (r + 1) >> 1;
}

/* return the inverse of the finite field element x */

static uint_8t fi(const uint_8t x)
{   uint_8t p1 = x, p2 = BPOLY, n1 = hibit(x), n2 = 0x80, v1 = 1, v2 = 0;

    if(x < 2) return x;

    for(;;)
    {
        if(!n1) return v1;

        while(n2 >= n1)
        {
            n2 /= n1; p2 ^= p1 * n2; v2 ^= v1 * n2; n2 = hibit(p2);
        }

        if(!n2) return v2;

        while(n1 >= n2)
        {
            n1 /= n2; p1 ^= p2 * n1; v1 ^= v2 * n1; n1 = hibit(p1);
        }
    }
}

#endif

/* The forward and inverse affine transformations used in the S-box */

#define fwd_affine(x) \
    (w = (uint_32t)x, w ^= (w<<1)^(w<<2)^(w<<3)^(w<<4), 0x63^(uint_8t)(w^(w>>8)))

#define inv_affine(x) \
    (w = (uint_32t)x, w = (w<<1)^(w<<3)^(w<<6), 0x05^(uint_8t)(w^(w>>8)))

static int init = 0;

#ifdef TC_WINDOWS_BOOT

#pragma optimize ("l", on)
uint_8t aes_enc_tab[256][8];
uint_8t aes_dec_tab[256][8];

#endif

AES_RETURN aes_init(void)
{   uint_32t  i, w;

#ifdef TC_WINDOWS_BOOT

	if (init)
		return EXIT_SUCCESS;

    for (i = 0; i < 256; ++i)
    { 
        uint_8t x = fwd_affine(fi((uint_8t)i));
		aes_enc_tab[i][0] = 0;
		aes_enc_tab[i][1] = x;
		aes_enc_tab[i][2] = x;
		aes_enc_tab[i][3] = f3(x);
		aes_enc_tab[i][4] = f2(x);
		aes_enc_tab[i][5] = x;
		aes_enc_tab[i][6] = x;
		aes_enc_tab[i][7] = f3(x);

        x = fi((uint_8t)inv_affine((uint_8t)i));
		aes_dec_tab[i][0] = fe(x);
		aes_dec_tab[i][1] = f9(x);
		aes_dec_tab[i][2] = fd(x);
		aes_dec_tab[i][3] = fb(x);
		aes_dec_tab[i][4] = fe(x);
		aes_dec_tab[i][5] = f9(x);
		aes_dec_tab[i][6] = fd(x);
		aes_dec_tab[i][7] = x;
    }

#else // TC_WINDOWS_BOOT

#if defined(FF_TABLES)

    uint_8t  pow[512], log[256];

    if(init)
        return EXIT_SUCCESS;
    /*  log and power tables for GF(2^8) finite field with
        WPOLY as modular polynomial - the simplest primitive
        root is 0x03, used here to generate the tables
    */

    i = 0; w = 1;
    do
    {
        pow[i] = (uint_8t)w;
        pow[i + 255] = (uint_8t)w;
        log[w] = (uint_8t)i++;
        w ^=  (w << 1) ^ (w & 0x80 ? WPOLY : 0);
    }
    while (w != 1);

#else
    if(init)
        return EXIT_SUCCESS;
#endif

    for(i = 0, w = 1; i < RC_LENGTH; ++i)
    {
        t_set(r,c)[i] = bytes2word(w, 0, 0, 0);
        w = f2(w);
    }

    for(i = 0; i < 256; ++i)
    {   uint_8t    b;

        b = fwd_affine(fi((uint_8t)i));
        w = bytes2word(f2(b), b, b, f3(b));

#if defined( SBX_SET )
        t_set(s,box)[i] = b;
#endif

#if defined( FT1_SET )                 /* tables for a normal encryption round */
        t_set(f,n)[i] = w;
#endif
#if defined( FT4_SET )
        t_set(f,n)[0][i] = w;
        t_set(f,n)[1][i] = upr(w,1);
        t_set(f,n)[2][i] = upr(w,2);
        t_set(f,n)[3][i] = upr(w,3);
#endif
        w = bytes2word(b, 0, 0, 0);

#if defined( FL1_SET )            /* tables for last encryption round (may also   */
        t_set(f,l)[i] = w;        /* be used in the key schedule)                 */
#endif
#if defined( FL4_SET )
        t_set(f,l)[0][i] = w;
        t_set(f,l)[1][i] = upr(w,1);
        t_set(f,l)[2][i] = upr(w,2);
        t_set(f,l)[3][i] = upr(w,3);
#endif

#if defined( LS1_SET )			/* table for key schedule if t_set(f,l) above is*/
        t_set(l,s)[i] = w;      /* not of the required form                     */
#endif
#if defined( LS4_SET )
        t_set(l,s)[0][i] = w;
        t_set(l,s)[1][i] = upr(w,1);
        t_set(l,s)[2][i] = upr(w,2);
        t_set(l,s)[3][i] = upr(w,3);
#endif

        b = fi(inv_affine((uint_8t)i));
        w = bytes2word(fe(b), f9(b), fd(b), fb(b));

#if defined( IM1_SET )			/* tables for the inverse mix column operation  */
        t_set(i,m)[b] = w;
#endif
#if defined( IM4_SET )
        t_set(i,m)[0][b] = w;
        t_set(i,m)[1][b] = upr(w,1);
        t_set(i,m)[2][b] = upr(w,2);
        t_set(i,m)[3][b] = upr(w,3);
#endif

#if defined( ISB_SET )
        t_set(i,box)[i] = b;
#endif
#if defined( IT1_SET )			/* tables for a normal decryption round */
        t_set(i,n)[i] = w;
#endif
#if defined( IT4_SET )
        t_set(i,n)[0][i] = w;
        t_set(i,n)[1][i] = upr(w,1);
        t_set(i,n)[2][i] = upr(w,2);
        t_set(i,n)[3][i] = upr(w,3);
#endif
        w = bytes2word(b, 0, 0, 0);
#if defined( IL1_SET )			/* tables for last decryption round */
        t_set(i,l)[i] = w;
#endif
#if defined( IL4_SET )
        t_set(i,l)[0][i] = w;
        t_set(i,l)[1][i] = upr(w,1);
        t_set(i,l)[2][i] = upr(w,2);
        t_set(i,l)[3][i] = upr(w,3);
#endif
    }

#endif // TC_WINDOWS_BOOT

    init = 1;
    return EXIT_SUCCESS;
}

#endif

