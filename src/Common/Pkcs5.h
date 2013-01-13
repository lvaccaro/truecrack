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
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_PKCS5
#define TC_HEADER_PKCS5

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

void hmac_sha512 (char *k, int lk, char *d, int ld, char *out, int t);
void derive_u_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_key_sha512 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
void hmac_sha1 (char *k, int lk, char *d, int ld, char *out, int t);
void derive_u_sha1 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_key_sha1 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
void hmac_ripemd160 (char *key, int keylen, char *input, int len, char *digest);
void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
void hmac_whirlpool (char *k, int lk, char *d, int ld, char *out, int t);
void derive_u_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
void derive_key_whirlpool (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);
int get_pkcs5_iteration_count (int pkcs5_prf_id, BOOL bBoot);
char *get_pkcs5_prf_name (int pkcs5_prf_id);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_PKCS5
