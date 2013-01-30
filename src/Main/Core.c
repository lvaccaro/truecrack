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
	printf("%s v%s\n", SOFTWARE,VERSION);
	printf("Website: %s\n",WEBSITE);
	printf("Contact us: %s\n",EMAIL);
	
	if (CORE_typeAttack==ATTACK_DICTIONARY)
		core_dictionary();
	else if (CORE_typeAttack==ATTACK_CHARSET)
		core_charset();
	else 
	  printf("Select an invalid operation mode\n");
}


#ifdef _GPU_
void core_dictionary(void) {

    /* Local variables */
    FILE *fp_words;			// file structures for words file
    short int status=0;			// value for the found rigth key
    int i,j,k;				// counters for temporany cycles
    int block_size=0, iblock=0;		// counters for block

    /* 1. Init procedure  */
    // Retrieve block size dimension

   if (CORE_blocksize==0) 
	CORE_blocksize=1024;//getMultiprocessorCount();
   
    // Allocation of variables and structures
    blockPwd=malloc(CORE_blocksize*PASSWORD_MAXSIZE*sizeof(char));
    blockPwd_init=malloc(CORE_blocksize*sizeof(int));
    blockPwd_length=malloc(CORE_blocksize*sizeof(int));
   // Open file of passwords
    fp_words=file_open(CORE_wordsPath);
    // Read in volume header
    header_length = file_readHeader(CORE_volumePath,header);
    // Allocation and initialization memory of constant structures for cuda procedure
    unsigned char salt[PKCS5_SALT_SIZE];
    memcpy (salt, header + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    cuda_Init (CORE_blocksize, salt,header) ;

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

 	result=malloc(block_size*sizeof(short int));	
	if (result==NULL){
		perror("Memory could not be allocated. ");
		exit( EXIT_FAILURE );
	}
        // 2.2 Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
        // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
        cuda_Core_dictionary (block_size,blockPwd, blockPwd_init, blockPwd_length, result, CORE_keyDerivationFunction);

	for (i=0;i<block_size && status!=1 ;i++) {
		if(result[i]==MATCH)
			status=1;
	} 

        if (CORE_verbose) {
            for (j=0;j<block_size;j++) {
                //printf("%d result : %02x\n", i, (unsigned char) (result[i]));
                printf("%d >> ",j);
                for (k=0;k<blockPwd_length[j];k++)
                    printf("%c",blockPwd[blockPwd_init[j]+k]);
                printf(" : ");
		switch(result[j]){
		  case MATCH: 
			printf("MATCH\n");
			break;
		  case NOMATCH:
			printf("NO MATCH\n");
			break;
		  default:
			printf("ERROR\n");
		}
            }
        }
	free(result);
        iblock++;
    }
    iblock--;
    i--;

    /* 3. Close procedure */
    file_close(fp_words);

    /* 4. Print output message*/
    uint64_t offset=iblock*CORE_blocksize+i;
    if (status==1) {
        // Retrieve the master key from last block
        int j;
	offset+=i;
        printf("Found password: \"");
	for (j=0;j<blockPwd_length[i];j++)
            printf("%c",blockPwd[blockPwd_init[i]+j]);
        printf("\" of length \"%d\", try \"%d\" words.\n",blockPwd_length[i]-1,offset);	
	
    } else {
	printf("No found password: try \"%d\" words.\n",offset);

    }
    free(blockPwd);
    free(blockPwd_init);
    free(blockPwd_length);
    cuda_Free () ;

}
#else
void core_dictionary(void) {

    /* Local variables */
    FILE *fp_words;			// file structures for words file
    short int status=0;			// value for the found rigth key
    int j;				// counters for temporany cycles
    int block_size=0, iblock=0;		// counters for block

	/* 1. Init procedure  */   
	// Allocation of variables and structures
	blockPwd=malloc(PASSWORD_MAXSIZE*sizeof(char));
	blockPwd_init=malloc(sizeof(int));
	blockPwd_length=malloc(sizeof(int));
	result=malloc(sizeof(short int));
	if (result==NULL){
		perror("Memory could not be allocated. ");
		exit( EXIT_FAILURE );
	}
	// Open file of passwords
	fp_words=file_open(CORE_wordsPath);
	// Read in volume header
	header_length = file_readHeader(CORE_volumePath,header);

    /* 2. Block procedure
     * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
     * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
     * a block is implement how a single array of sequentially words; there are also provide
     * support vector init and length for each words.
     */
    while ( status!=1 ) {

        // 2.1 Fill the BlockPwd of passwords and detect the new dimension block.
        // The size of block can change to the number of the read words when the read function go to the end of file.
        block_size=file_readWordsBlock(fp_words, 1,blockPwd,blockPwd_init,blockPwd_length);
        if (block_size==0)
            break;

        if (CORE_verbose) {
		printf("%d >> ",iblock);
                for (j=0;j<blockPwd_length[0];j++)
                    printf("%c",blockPwd[j]);
		printf(" : ");
        }


        cpu_Core_dictionary(1, header, blockPwd, blockPwd_init, blockPwd_length, result, CORE_keyDerivationFunction);
	
	if(result[0]==MATCH)
		status=1;

        if (CORE_verbose) {
		switch(result[0]){
		  case MATCH: 
			printf("MATCH\n");
			break;
		  case NOMATCH:
			printf("NO MATCH\n");
			break;
		  default:
			printf("ERROR\n");
		}
        }
        iblock++;
    }
    iblock--;


    /* 3. Close procedure */
    file_close(fp_words);

    /* 4. Print output message*/
    uint64_t offset=iblock;
    if (status==1) {
        // Retrieve the master key from last block
        int j;
        printf("Found password: \"");
	for (j=0;j<blockPwd_length[0];j++)
            printf("%c",blockPwd[j]);
        printf("\" of length \"%d\", try \"%d\" words.\n",blockPwd_length[0],offset);	
    } else {
	    printf("No found password: try \"%d\" words.\n",offset);
    }
    free(blockPwd);
    free(blockPwd_init);
    free(blockPwd_length);
}
#endif



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


#ifdef _GPU_
void core_charset(void) {

    /* Local variables */
    short int status=0;			// value for the found rigth key
    uint64_t i,j,k;			// counters for temporany cycles
    
    /* 1. Init procedure  */
    // Read in volume header
    header_length = file_readHeader(CORE_volumePath,header);

    // Allocation and initialization memory of constant structures for cuda procedure
    unsigned char salt[PKCS5_SALT_SIZE];
    memcpy (salt, header + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);
    cuda_Init (CORE_blocksize, salt,header) ;

    /* 2. Block procedure
     * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
     * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
     * a block is implement how a single array of sequentially words; there are also provide
     * support vector init and length for each words.
     */
    unsigned char word[MAXWORDSIZE];
    unsigned short int wordlength;
    uint64_t maxcombination=1;
    CORE_maxlength++;

    for ( wordlength=CORE_minlength; wordlength <  CORE_maxlength && status==0; wordlength++) {
      maxcombination=1;
	for (i=0;i<wordlength;i++)
		maxcombination*= strlen(CORE_charset);

	result=malloc(maxcombination*sizeof(short int));
	if (result==NULL){
		perror("Memory could not be allocated. ");
		exit( EXIT_FAILURE );
	}
        // 2.2 Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
        // PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
    
	cuda_Core_charset ( strlen(CORE_charset), CORE_charset, wordlength, result, CORE_keyDerivationFunction) ;
        for (i=0;i<maxcombination && status!=1 ;i++) {
		if(result[i]==MATCH)
 			status=1;
	} 
        if (CORE_verbose) {
		for (j=0;j<maxcombination;j++) {
			computePwd_ (j, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
			word[wordlength]='\0';		
			/*printf("maxcombination=%d\n",maxcombination);
			printf("j=%d\n",j);
			printf("wordlength=%d\n",wordlength);
			printf("word=%s\n",word);
			printf("result[%d]=%d\n",j,result[j]);
			*/
			printf("%d - %d / %d >> ",wordlength,(int)j,(int)maxcombination);
			for (k=0;k<wordlength;k++)
				printf("%c",word[k]);
			printf(" : ");
			switch(result[j]){
			  case MATCH: 
				printf("MATCH\n");
				break;
			  case NOMATCH:
				printf("NO MATCH\n");
				break;
			  default:
				printf("ERROR\n");
			}
		}
        }
        free(result);
    }
    wordlength--;
    i--;

    /* 4. Print output message*/
    	int l;
	uint64_t offset=0;
	for (k=CORE_minlength;k<=wordlength;k++){
		maxcombination=1;
		for (l=0;l<k;l++)
			maxcombination*=strlen(CORE_charset);
		offset+=maxcombination;
	}
	if (status==1) {
		// Retrieve the master key from last block
		maxcombination=1;
		for (l=0;l<wordlength;l++)
			maxcombination*=strlen(CORE_charset);
		computePwd_ (i, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
		word[wordlength]='\0';
		offset+=i;
		printf("Found password: \"%s\" of length \"%d\", try \"%d\" words.\n",(char*)word,wordlength,offset);
	} else {
		printf("No found password: try \"%d\" words.\n",offset);
	}

    cuda_Free () ;

}

#else

void core_charset(void) {

	/* Local variables */
	short int status=0;			// value for the found rigth key
	uint64_t i,j;				// counters for temporany cycles
	
	/* 1. Init procedure  */
	// Read in volume header
	header_length = file_readHeader(CORE_volumePath,header);

	// Allocation and initialization memory of constant structures for cuda procedure
	unsigned char salt[PKCS5_SALT_SIZE];
	memcpy (salt, header + HEADER_SALT_OFFSET, PKCS5_SALT_SIZE);

	/* 2. Crypt procedure */
	unsigned char word[MAXWORDSIZE];
	unsigned short int wordlength=1;
	unsigned short int maxcombination=1;
	CORE_maxlength++;
	int ret=0;
	
	for (wordlength=CORE_minlength;wordlength<CORE_maxlength && status==0;wordlength++){
		ret=cpu_Core_charset ( header, CORE_charset, wordlength,CORE_verbose,CORE_keyDerivationFunction);
		if (ret>0)
			status=1;
	}
	wordlength--;
	
	/* 3. Print output message*/
	uint64_t l,k;
	uint64_t offset=0;
	for (k=CORE_minlength;k<=wordlength;k++){
		maxcombination=1;
		for (l=0;l<k;l++)
			maxcombination*=strlen(CORE_charset);
		offset+=maxcombination;
	}
	if (status==1) {
		// Retrieve the master key from last block
		maxcombination=1;
		for (l=0;l<wordlength;l++)
			maxcombination*=strlen(CORE_charset);
		computePwd_ (ret, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
		word[wordlength]='\0';
		printf("Found password: \"%s\" of length \"%d\", try \"%d\" words.\n",(char*)word,wordlength,offset);
	} else {
		printf("No found password: try \"%d\" words.\n",offset);
	}
}
#endif

