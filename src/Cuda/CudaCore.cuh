/*
 * Copyright (C)  2011  Luca Vaccaro
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

#ifndef TC_HEADER_CUDACORE
#define TC_HEADER_CUDACORE


#define PASSWORD_MAXSIZE	32
#define SALT_LENGTH 		64
#define ITERATIONS		2000

#if defined(__cplusplus)
extern "C"
{
#endif



int getMultiprocessorCount (void);
void cuda_Init (int block_maxsize, unsigned char *salt, unsigned char *header);
void cuda_Set (	int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result);
void cuda_Free(void);
void cuda_Core ( int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result);
void cuda_Core_dictionary ( int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result);

void cuda_Core_charset ( unsigned short int charset_length, unsigned char *charset, unsigned short int password_length, short int *result) ;
#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_CUDACORE
