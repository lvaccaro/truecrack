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
#include <string.h>
#include "Utils.h"
#include "Volumes.h"
#include "Core.h"
#include "Charset.h"
#ifdef _GPU_
  #include "CudaCore.cuh"
  #include "CudaXts.cuh"
#else
  #include "CpuCore.h"
#endif

/* Buffer with header */
char header[512]={0};
int header_length;

/* Block of passwords */
char *blockPwd;
int *blockPwd_init, *blockPwd_length;

/* Block of check result */
short int *result;

void core_dictionary(void);
void core_charset(void);

void core(void){
	if (CORE_typeAttack==ATTACK_DICTIONARY)
		core_dictionary();
	else if (CORE_typeAttack==ATTACK_CHARSET)
		core_charset();
	else 
	  printf("Select an invalid operation mode\n");
}

void core_dictionary(void) {

    /* Local variables */
    FILE *fp_words;			// file structures for words file
    short int status=0;			// value for the found rigth key
    int i,j;				// counters for temporany cycles
    int block_size=0, iblock=0;		// counters for block

    /* 1. Init procedure  */
    // Retrieve block size dimension
#ifdef _GPU_
   if (CORE_blocksize==0) 
	CORE_blocksize=getMultiprocessorCount();
#else
   if (CORE_blocksize==0)
   	CORE_blocksize=BLOCK_SIZE;
#endif
   
    // Allocation of variables and structures
    blockPwd=malloc(CORE_blocksize*PASSWORD_MAXSIZE*sizeof(char));
    blockPwd_init=malloc(CORE_blocksize*sizeof(int));
    blockPwd_length=malloc(CORE_blocksize*sizeof(int));
    result=malloc(10000*sizeof(int));
    // Open file of passwords
    fp_words=file_open(CORE_wordsPath);
    // Read in volume header
    header_length = file_readHeader(CORE_volumePath,header);
#ifdef _GPU_
    // Allocation and initialization memory of constant structures for cuda procedure
    unsigned char salt[PKCS5_SALT_SIZE];
    memcpy (salt, header + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    cuda_Init (CORE_blocksize, salt,header) ;
#endif


    /* 2. Block procedure
     * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
     * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
     * a block is implement how a single array of sequentially words; there are also provide
     * support vector init and length for each words.
     */
    while ( status!=1 ) {

        // 2.1 Fill the BlockPwd of passwords and detect the new dimension block.
        // The size of block can change to the number of the read words when the read function go to the end of file.
        block_size=file_readWordsBlock(fp_words, CORE_blocksize,blockPwd,blockPwd_init,blockPwd_length);
        if (block_size==0)
            break;

        if (CORE_verbose) {
            for (i=0;i<block_size;i++) {
                printf("%d password : ",i);
                for (j=0;j<blockPwd_length[i];j++)
                    printf("%c",blockPwd[blockPwd_init[i]+j]);
                printf("\n");
            }
        }

#ifdef _GPU_
        // 2.2 Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
        // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
        cuda_Core_dictionary (block_size,blockPwd, blockPwd_init, blockPwd_length, result);
//        cuda_Core(result);	
#else
        cpu_Core(block_size, header, blockPwd, blockPwd_init, blockPwd_length, result);
	
#endif
        for (i=0;i<block_size && status!=1 ;i++) {
		if(result[i]==MATCH)
			status=1;
	} 

        if (CORE_verbose) {
            for (j=0;j<block_size;j++) {
                //printf("%d result : %02x\n", i, (unsigned char) (result[i]));
                printf("%d result : ", j);
		switch(result[j]){
		  case MATCH: 
			printf("MATCH\n");
			break;
		  case NOMATCH:
			printf("NO MATCH\n");
			break;
		  default:
			printf("NOT DEFINED\n");
		}
            }
        }

        iblock++;
    }
    iblock--;
    i--;


    /* 3. Close procedure */
    file_close(fp_words);

    /* 4. Print output message*/
    if (status==1) {
        // Retrieve the master key from last block
        int j;

        printf("Found password for volume \"%s\" in words file \"%s\"\n",CORE_volumePath,CORE_wordsPath);
    
        printf("Password[%d]: ",blockPwd_length[i]-1);
        for (j=0;j<blockPwd_length[i];j++)
            printf("%c",blockPwd[blockPwd_init[i]+j]);
        printf("\n");
	
    } else {
        printf("Not Found password for volume \"%s\"\n",CORE_volumePath);
        printf("Try \"%d\" words.\n",iblock*CORE_blocksize+i);

    }
    free(blockPwd);
    free(blockPwd_init);
    free(blockPwd_length);
    free(result);
#ifdef _GPU_
    cuda_Free () ;
#endif

}



void computePwd_ (int number, int maxcombination, int charsetlength, unsigned char *charset, int wordlength, unsigned char *word){
    unsigned short i=0;
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



void core_charset(void) {

    /* Local variables */
    short int status=0;			// value for the found rigth key
    int i,j;				// counters for temporany cycles
    
    /* 1. Init procedure  */
    // Read in volume header
    header_length = file_readHeader(CORE_volumePath,header);
#ifdef _GPU_
    // Allocation and initialization memory of constant structures for cuda procedure
    unsigned char salt[PKCS5_SALT_SIZE];
    memcpy (salt, header + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    cuda_Init (CORE_blocksize, salt,header) ;
#endif


    /* 2. Block procedure
     * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
     * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
     * a block is implement how a single array of sequentially words; there are also provide
     * support vector init and length for each words.
     */
    unsigned char word[32];
    unsigned short int wordlength=1;
    unsigned short int maxcombination=1;
    CORE_maxlength++;

    while ( wordlength <  CORE_maxlength) {
      maxcombination=1;
	for (i=0;i<wordlength;i++)
		maxcombination*= strlen(CORE_charset);
	
	
	
        if (CORE_verbose) {
	    for (i=0;i<maxcombination;i++) {
		computePwd_ (i, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
		word[wordlength]='\0';
		printf("%d/%d password : %s\n",i,maxcombination,word);
            }
        }

#ifdef _GPU_
        // 2.2 Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
        // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
        result=malloc(10000*sizeof(short int));
    
	cuda_Core_charset ( strlen(CORE_charset), CORE_charset, wordlength, result) ;
	
#else
        printf("This implementation takes too much.. try with cuda\n");
#endif
        for (i=0;i<maxcombination && status!=1 ;i++) {
		if(result[i]==MATCH)
			status=1;
	} 

        if (CORE_verbose) {
            for (j=0;j<maxcombination;j++) {
                //printf("%d result : %02x\n", i, (unsigned char) (result[i]));
                printf("%d result : ", j);
		switch(result[j]){
		  case MATCH: 
			printf("MATCH\n");
			break;
		  case NOMATCH:
			printf("NO MATCH\n");
			break;
		  default:
			printf("NOT DEFINED\n");
		}
            }
        }
        free(result);

        wordlength++;
    }
    wordlength--;
    i--;


    /* 4. Print output message*/
    if (status==1) {
        // Retrieve the master key from last block
        int j;

        printf("Found password for volume \"%s\" in the charset \"%s\" of max length %d\n",CORE_volumePath,CORE_charset,CORE_maxlength);
	computePwd_ (i, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
	printf("password: %s - length: %d\n",word,wordlength);

	
    } else {
        printf("Not Found password for volume \"%s\"\n",CORE_volumePath);
        printf("Try \"%d\" words.\n",i);

    }
#ifdef _GPU_
    cuda_Free () ;
#endif

}
