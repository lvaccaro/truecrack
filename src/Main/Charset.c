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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "Charset.h"

/*La funzione numberOfStrings dice di quante parole è composta la permutazione completa di n caratteri in alfabeto per stringhe lunghe da 1 a n caratteri (è di supporto).*/
unsigned long numberOfStrings(const int alphLength, const int stringMinLength, const int stringMaxLength) {
    unsigned long res = 0;
    int i;
    for (i=stringMinLength;i<=stringMaxLength;i++) {
        res += pow(alphLength,i);
    }
    return res;
}

/*La funzione indexedWordFromAlphabet da la i-esima parola dell’elenco delle permutazioni di n caratteri in alfabeto per stringhe da 1 a n caratteri di lunghezza massima.
*/
char* indexedWordFromAlphabet (unsigned long idx, const char* alphCharset, const int alphLength, const int minWordLength, const int maxWordLength) {

    if (idx >= numberOfStrings(alphLength,minWordLength,maxWordLength)) {
        return NULL;
    }

    char* genWord = (char*) malloc(sizeof(char)*(maxWordLength+1));

    //Ciclo 0, primo carattere NON null
    genWord[0] = alphCharset[idx % alphLength];
    //Ciclo i-esimo
    int i, charIdx;
    for (i=minWordLength;i<(maxWordLength+1);i++) {
        if (idx<numberOfStrings(alphLength,minWordLength,i)) {
            genWord[i] = '\0';
            break;
        } else {
            charIdx = (idx-numberOfStrings(alphLength,minWordLength,i)) / (int) pow(alphLength,i);
            genWord[i] = alphCharset[charIdx % alphLength];
        }
    }

    return genWord;
}

int charset_readWordsBlock (int block_size, char *alphabet, int minlength, int maxlength,char *words, int *words_init, int *words_length) {

    char *buffer;
    static int count=0;
    int i;

    if (count >= numberOfStrings(strlen(alphabet),minlength,maxlength))
        return 0;

    for (i=0;i<block_size && count+i<numberOfStrings(strlen(alphabet),minlength,maxlength);i++) {
        //printf("* %s\n",indexedWordFromAlphabet(i+j,"abc",3,3));
	
        if (i==0)
            words_init[0]=0;
        else
            words_init[i]=words_init[i-1]+words_length[i-1];

        buffer=indexedWordFromAlphabet(i+count,alphabet,strlen(alphabet),minlength,maxlength);
	//printf (">>> %d [%d] /%d: %s\n",i,strlen(buffer),numberOfStrings(strlen(alphabet),minlength,maxlength),buffer);
        words_length[i]=strlen(buffer);

        memcpy(words+words_init[i],buffer,strlen(buffer));

        words[words_init[i]+strlen(buffer)]='\0'; //remember the \0

    }
    count+=i;
    return i;
}
/*
int main()
{
    printf("Example of word list from alphabet='a,b,c' and maxLength=3\n\n");
    int i,j;
    for(i=0;i<numberOfStrings(3,3);){
      for (j=0;j<3 && i<numberOfStrings(3,3);j++)
	  printf("* %s\n",indexedWordFromAlphabet(i+j,"abc",3,3));
      i+=j;
    }
    printf("--DONE!\n");
    return 0;
}
*/
