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

/* Support Large File */
#define _FILE_OFFSET_BITS 64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

 
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
 

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <time.h>

#include "Volumes.h"
#include "Tcdefs.h"
#include "Utils.h"
#include "Crypto.h"

//#ifdef _GPU_
//#include "CudaPkcs5.cuh"
//#else
#include "Pkcs5.h"
#include "CpuAes.h"
//#endif

FILE *file_open (char *wordPath) {
    int i;
    FILE *fp;

    fp=fopen(wordPath,"r");
    if (fp == NULL) {
        perror ("Error opening volume file");
        return NULL;
    }
    return fp;

}

void computePwd (uint64_t number, uint64_t maxcombination, uint8_t charsetlength, unsigned char *charset, uint8_t wordlength, unsigned char *word){
    uint8_t i=0;
    if (number>=maxcombination) return;
    for (i=0;i<wordlength;i++)
        word[i]=0;
    i=0;
    while(number>0){
        word[i]=number%charsetlength;
        number=(number-word[i])/charsetlength;
        i++;
    }
    for (i=0;i<wordlength;i++)
        word[i]=charset[word[i]];
}


int file_close (FILE *fp) {
    fclose(fp);
    return 1;
}

int file_readWordsBlock (FILE *fp, int block_size, char *words, int *words_init, int *words_length) {
    char buffer[MAXWORDSIZE];
    int i=0;

    for (i=0;i<block_size;i++) {
        if (fgets (buffer , MAXWORDSIZE , fp) == NULL)
            return i;
        if (i==0)
            words_init[0]=0;
        else
            words_init[i]=words_init[i-1]+words_length[i-1];

        words_length[i]=strlen(buffer);
        memcpy(words+words_init[i],buffer,strlen(buffer));
        words[words_init[i]+strlen(buffer)-1]='\0'; //remmember the \0
    }

    return block_size;

}


int file_readHeader(char *volumePath, char *header) {
    FILE *fp;
    int i=0;

    fp=fopen(volumePath,"r");
    if (fp == NULL) {
        perror ("Error opening volume file");
        return ;
    }

    //header offset
    i=0;
    while (i<TC_VOLUME_HEADER_OFFSET) {
        fgetc(fp);
        i++;
    }
    //header data
    while (i<TC_VOLUME_HEADER_EFFECTIVE_SIZE) {
        header[i]=fgetc(fp);
        i++;
    }

    fclose(fp);

    return i;
}
