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
#ifndef HEADER_Utils
#define HEADER_Utils

#include <stdio.h>
#include <sys/types.h>
#include "Tcdefs.h"

#define MAXWORDSIZE	64

FILE *file_open ( char *wordPath);
int file_close (FILE *fp);
int file_readWordsBlock (FILE *fp, int block_size, char *words, int *words_init, int *words_length);
int file_readHeader(char *volumePath, char *header);

//int readWords(char *wordPath, char *words[]);

void computePwd (uint64_t number, uint64_t maxcombination, uint8_t charsetlength, unsigned char *charset, uint8_t wordlength, unsigned char *word);


void cuda_initHeaderKey (char *encryptedHeader, int block_size ) ;
void cuda_calcHeaderKey(char *blockPwd, int *blockPwd_init, int *blockPwd_length,
		  char *blockHeaderKey, int *blockHeaderKey_init, int *blockHeaderKey_length);
void calcHeaderKey(char *encryptedHeader, int block_size,  char *blockPwd, int *blockPwd_init, int *blockPwd_length,
		  char *blockHeaderKey, int *blockHeaderKey_init, int *blockHeaderKey_length);
int decryptHeader(char *encryptedHeader, char *headerKey, int headerKey_length, char *masterKey, int *masterKey_length);
#ifndef _GPU_
void find_key_and_decrypt(int blocksize, unsigned char *encryptedHeader, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, int *result); 
#endif


#endif
