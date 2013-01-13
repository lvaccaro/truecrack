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
#ifndef HEADER_Charset
#define HEADER_Charset

/*La funzione numberOfStrings dice di quante parole è composta la permutazione completa di n caratteri in alfabeto per stringhe lunghe da 1 a n caratteri (è di supporto).*/
unsigned long numberOfStrings(const int alphLength, const int stringLength);

/*La funzione indexedWordFromAlphabet da la i-esima parola dell’elenco delle permutazioni di n caratteri in alfabeto per stringhe da 1 a n caratteri di lunghezza massima.
*/
char* indexedWordFromAlphabet (unsigned long idx, const char* alphCharset, const int alphLength, const int maxWordLength);

#endif