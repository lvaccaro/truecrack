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
#ifndef HEADER_CORE
#define HEADER_CORE

#define SOFTWARE	"TrueCrack"
#define VERSION		"2.9"
#define WEBSITE		"http://code.google.com/p/truecrack"
#define AUTHOR		"Luca Vaccaro"
#define EMAIL		"infotruecrack@gmail.com"
#define MESSAGE 	"Bruteforce password cracker for Truecrypt volume. Optimazed with Nvidia Cuda technology.\nBased on TrueCrypt, freely available at http://www.truecrypt.org/\nCopyright (c) 2011 by Luca Vaccaro."


#define BLOCK_SIZE 	1024

/* Support bruteforce. */
enum {
    ATTACK_DICTIONARY,
    ATTACK_CHARSET
};

/* The name of the file of words */
char *CORE_wordsPath;
/* The name of the file of truecrypt volume */
char *CORE_volumePath;
/* The charset string */
unsigned char *CORE_charset;
/*The max length of words generated from charset */
int CORE_maxlength;
/*The min length of words generated from charset */
int CORE_minlength;
/* The type of attack */
int CORE_typeAttack;
/* Size of the block of parallel words*/
int CORE_blocksize;
/* Whether to display verbose messages. */
int CORE_verbose;
/* Key derivation function. */
int CORE_keyDerivationFunction;

/* Main function */
void core(void);

#endif
