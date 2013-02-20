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
#ifndef CPUCORE_H
#define CPUCORE_H

// Header files (optional)

#include "Tcdefs.h"
#include "Common/Endian.h"
#include "Crypto.h"

#define PASSWORD_MAXSIZE 32

enum{
  NODEFINED,
  MATCH,
  NOMATCH,
};

int cpu_Core_dictionary(int blocksize, unsigned char *encryptedHeader, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int keyDerivationFunction) ;
void cpu_Core_charset(unsigned char *encryptedHeader, unsigned char *CORE_charset, unsigned char *word, int wordlength, int keyDerivationFunction) ;
#endif
