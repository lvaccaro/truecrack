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
#define VERSION		"2.1"
#define WEBSITE		"http://code.google.com/p/truecrack"
#define AUTHOR		"Luca Vaccaro"
#define EMAIL		"infotruecrack@gmail.com"
#define MESSAGE 	"Bruteforce password cracker for Truecrypt volume. Optimazed with Nvidia Cuda technology.\nBased on TrueCrypt, freely available at http://www.truecrypt.org/\nCopyright (c) 2011 by Luca Vaccaro."


#define BLOCK_SIZE 	1024

/* Type of supported bruteforce. */
enum {
    ATTACK_DICTIONARY,
    ATTACK_CHARSET
};

int CORE_typeAttack;
int CORE_verbose;
char *CORE_volumePath;
char *CORE_wordsPath;
unsigned char *CORE_charset;
int CORE_maxlength;
int CORE_blocksize;

void core(void);

#endif
