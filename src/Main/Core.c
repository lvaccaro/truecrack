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
#include <signal.h>
#include <stdlib.h>
#include "Utils.h"
#include "Core.h"

#include "Charset.h"
#ifdef _GPU_
#include "Core.cuh"
#else
#include "Volumes.h"
#include "CpuCore.h"
#endif

/* Buffer with header */
char header[512]={0};
int header_length;
unsigned char salt[SALT_LENGTH];

/* Password */
unsigned char password[MAXWORDSIZE];
int password_size=0;

/* Block of passwords */
char *blockPwd;
int *blockPwd_init, *blockPwd_length;
short int *result;

/* Wordlist file */
FILE *fp_words;

/* Counters */
long long int block_size=0, iblock=0;
int i=0;
unsigned short int wordlength=1;
unsigned long long int count=0;
unsigned short status=0;

/* Functions */
void core_dictionary(void);
void core_charset(void);
void core(void);
void core_init(void);
void core_close(void);
void signalHandler(int signo);

void core_close(void){
	if (CORE_typeAttack==ATTACK_DICTIONARY){
		fclose(fp_words);
		free(blockPwd);
		free(blockPwd_init);
		free(blockPwd_length);
	}
	free(result);
#ifdef _GPU_
	cuda_Free();
#endif
	exit(0);
}

void core_init(void){
	
	//Check the truecrypt volume file
	FILE *fp;
	if ((fp=fopen(CORE_volumePath,"r"))==NULL){
		printf("Error %s : No such file\n",CORE_volumePath);
		exit(0);
	}else
		fclose(fp);
	
	if (CORE_typeAttack==ATTACK_DICTIONARY){
		if ((fp=fopen(CORE_wordsPath,"r"))==NULL){
			printf("Error %s : No such file\n",CORE_wordsPath);
			exit(0);
		}else
			fclose(fp);
	}
	
	//read the volume	
	header_length = file_readHeader(CORE_volumePath,header,CORE_backup,CORE_hidden);
	memcpy (salt, header + HEADER_SALT_OFFSET, SALT_LENGTH);

	if(CORE_verbose)
		printf("\nMemory initialization...\n");
	
	// Retrieve block size dimension
#ifdef _GPU_
	if (CORE_blocksize==0) 
		CORE_blocksize=1024;//getMultiprocessorCount();
	// Allocation and initialization memory of constant structures for cuda procedure
	cuda_Init (CORE_blocksize, salt,header) ;
#else
	CORE_blocksize=1;
#endif
	block_size=CORE_blocksize;
	
	// Allocation of variables and structures
	if (CORE_typeAttack==ATTACK_DICTIONARY){
		blockPwd=malloc(CORE_blocksize*PASSWORD_MAXSIZE*sizeof(char));
		blockPwd_init=malloc(CORE_blocksize*sizeof(int));
		blockPwd_length=malloc(CORE_blocksize*sizeof(int));
		fp_words=file_open(CORE_wordsPath);
	}
	result=malloc(CORE_blocksize*sizeof(short int));		
}



void signalHandler(int signo) {
	if (signo == SIGINT){
		printf("\n---BLOCKED---\n");
		printf("Computed blocks :\t\"%llu\"\n",iblock);
		printf("Size per block :\t\"%llu\"\n",block_size);
		printf("Current position:\t\"%d\"\n",i);
		printf("Total computations:\t\"%llu\"\n",count);
		core_close();
	}
}


void core(void){

	signal(SIGINT, signalHandler);

	printf("%s v%s\n", SOFTWARE,VERSION);
	printf("Website: %s\n",WEBSITE);
	printf("Contact us: %s\n",EMAIL);

	/* 1. Allocation and initialization of variables*/
	core_init();

	/* 2. Start computation */
	if (CORE_typeAttack==ATTACK_DICTIONARY)
		core_dictionary();
	else if (CORE_typeAttack==ATTACK_CHARSET)
		core_charset();
	else
		printf("Select an invalid operation mode\n");

	/* 3. Check the result */
	if (status==1) {
		printf("Found password:\t\t\"");
		int j;
		for (j=0;j<password_size;j++)
			printf("%c",password[j]);
		printf("\"\nPassword length:\t\"%d\"\n",password_size);
		printf("Total computations:\t\"%llu\"\n",count);	

	} else {
		printf("No found password\nTotal computations:\t\"%llu\"\n",count);

		/* 4. close files and free variables*/
		core_close();
	}

}
#ifdef _GPU_
	void core_dictionary(void) {

		/* Local variables */
		int j,k;				// counters for temporany cycles
		float time;

		/* Init procedure  */
		/* Block procedure
		 * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
		 * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
		 * a block is implement how a single array of sequentially words; there are also provide
		 * support vector init and length for each words.
		 */
		if (CORE_verbose)
			printf ( "\nCOUNT\tPASSWORD\tRESULT\n" );
		count=file_offset(fp_words, CORE_restore);
		
		while ( status!=1 ) {

			// 2.1 Fill the BlockPwd of passwords and detect the new dimension block.
			// The size of block can change to the number of the read words when the read function go to the end of file.
			block_size=file_readWordsBlock(fp_words, CORE_blocksize,blockPwd,blockPwd_init,blockPwd_length);
			if (block_size==0)
				break;

			// Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
			// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
			time=cuda_Core_dictionary (CORE_encryptionAlgorithm,block_size,blockPwd, blockPwd_init, blockPwd_length, result, CORE_keyDerivationFunction);
			
			for (i=0;i<block_size && status!=1 ;i++) {
				if(result[i]==1)
					status=1;
			} 

			if (CORE_verbose) {
				for (j=0;j<block_size;j++) {
					printf("%llu\t",count+j);
					for (k=0;k<blockPwd_length[j];k++)
						printf("%c",blockPwd[blockPwd_init[j]+k]);
					printf("\t");
					if (blockPwd_length[j]<=8)		
						printf("\t");
					if (result[j]==1)
						printf("YES\n");
					else
						printf("NO\n");
				}
				printf("--- Performance: %g p/s, time: %.2g s, passwords: %d \n",block_size/(time/1000),time/1000,block_size);
			}
			count+=block_size;
			iblock++;
		}
		iblock--;
		i--;

		if (status==1) {
			// Retrieve the master key from last block
			password_size=blockPwd_length[i];	
			memcpy(password,&blockPwd[blockPwd_init[i]],blockPwd_length[i]);
		}
	}
#else
	void core_dictionary(void) {

		/* Local variables */
		int j;				// counters for temporany cycles


		/* Block procedure
		 * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
		 * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
		 * a block is implement how a single array of sequentially words; there are also provide
		 * support vector init and length for each words.
		 */
		if (CORE_verbose)
			printf ( "\nCOUNT\tPASSWORD\tRESULT\n" );
		count=file_offset(fp_words, CORE_restore);
		
		while ( status!=1 ) {

			// Fill the BlockPwd of passwords and detect the new dimension block.
			// The size of block can change to the number of the read words when the read function go to the end of file.
			block_size=file_readWordsBlock(fp_words, 1,blockPwd,blockPwd_init,blockPwd_length);
			if (block_size==0)
				break;

			cpu_Core_dictionary(CORE_encryptionAlgorithm,1, header, blockPwd, blockPwd_init, blockPwd_length, result, CORE_keyDerivationFunction);
			
			if(result[0]==1)
				status=1;

			if (CORE_verbose) {
				printf("%llu\t",count);
				for (j=0;j<blockPwd_length[0];j++)
					printf("%c",blockPwd[j]);
				printf("\t");
				if (blockPwd_length[0]<=8)		
					printf("\t");
				if (result[0]==1)
					printf("YES\n");
				else
					printf("NO\n");
			}
			count++;
			iblock++;
		}
		iblock--;

		if (status==1) {
			// Retrieve the master key from last block
			password_size=blockPwd_length[0];	
			memcpy(password,&blockPwd[0],blockPwd_length[0]);
		}
	}
#endif


#ifdef _GPU_
	void core_charset(void) {

		/* Local variables */
		uint64_t j,k;			// counters for temporany cycles


		/* Block procedure
		 * The algoritm reads and computes NUM_OF_BLOCK passwords each time.
		 * Because Cuda Toolkit have problem to reference at pointer of pointer (matrix structure)
		 * a block is implement how a single array of sequentially words; there are also provide
		 * support vector init and length for each words.
		 */
		unsigned char word[MAXWORDSIZE];
		long long int maxcombination=1;
		long long int restore=CORE_restore;
		float time;
		CORE_maxlength++;

		if (CORE_verbose)
			printf ( "\nCOUNT\tPASSWORD\tRESULT\n" );

		for (wordlength=CORE_minlength;wordlength<CORE_maxlength;wordlength++){
			maxcombination=1;
			for (j=0;j<wordlength;j++)
				maxcombination*= strlen(CORE_charset);
			if (restore-maxcombination>0){
				restore-=maxcombination;
				count+=maxcombination;
			}else
				break;
		}
		if(restore<0){
			printf("Bad arguments\n");
			exit(0);
		}
		CORE_minlength=wordlength;
		count+=restore;
		
		for ( wordlength=CORE_minlength; wordlength <  CORE_maxlength && status==0; wordlength++) {
			maxcombination=1;
			for (i=0;i<wordlength;i++)
				maxcombination*= strlen(CORE_charset);
			
			if(wordlength==CORE_minlength)
				iblock=restore/CORE_blocksize;
			else
				iblock=0;

			for (;iblock<maxcombination/CORE_blocksize+1 && status==0;iblock+=1){

				block_size=CORE_blocksize;  
				if( iblock==maxcombination/CORE_blocksize )
					block_size=maxcombination%CORE_blocksize;

				// Calculate the hash header keys decrypt the encrypted header and check the right header key with cuda procedure
				// PKCS5 is used to derive the primary header key(s) and secondary header key(s) (XTS mode) from the password
				uint64_t offset=(uint64_t)(iblock*CORE_blocksize+restore);
				restore=0;
				//printf("iblock:%d / block_size:%d =>> %d / maxcombination: %d\n",iblock,(int)block_size,(int)offset,(int)maxcombination);

				cuda_Core_charset ( CORE_encryptionAlgorithm, block_size,offset, strlen(CORE_charset), CORE_charset, wordlength, result, CORE_keyDerivationFunction) ;
				
				for (i=0;i<block_size && status!=1 ;i++) {
					if(result[i]==1)
						status=1;
				} 
				if (CORE_verbose) {
					for (j=0;j<block_size;j++) {
						computePwd (iblock*CORE_blocksize+j, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
						word[wordlength]='\0';
						printf("%llu\t",count+j);
						for (k=0;k<wordlength;k++)
							printf("%c",word[k]);
						printf("\t");
						if (wordlength<=8)		
							printf("\t");						
						if (result[j]==1)
							printf("YES\n");
						else
							printf("NO\n");
						printf("--- Performance: %g p/s, time: %.2g s, passwords: %d \n",block_size/(time/1000),time/1000,block_size);
					}
				}
				count+=block_size;
			}
		}
		wordlength--;
		iblock--;
		i--;

		int l;
		uint64_t offset=0;
		for (k=CORE_minlength;k<wordlength;k++){
			maxcombination=1;
			for (l=0;l<k;l++)
				maxcombination*=strlen(CORE_charset);
			offset+=maxcombination;
		}
		offset+=iblock*CORE_blocksize+i+1;
		if (status==1) {
			// Retrieve the master key from last block
			maxcombination=1;
			for (l=0;l<wordlength;l++)
				maxcombination*=strlen(CORE_charset);
			password_size=wordlength;
			computePwd (offset-1, maxcombination, strlen(CORE_charset),CORE_charset, password_size, password);
			password[password_size]='\0';
		}


	}

#else

	void core_charset(void) {

		/* Local variables */
		uint64_t j;				// counters for temporany cycles


		/* Crypt procedure */
		unsigned char word[MAXWORDSIZE];
		wordlength=1;
		long long int maxcombination=1;
		long long int restore=CORE_restore;
		CORE_maxlength++;
		int length,value;
		i=0;

		if (CORE_verbose)
			printf ( "\nCOUNT\tPASSWORD\tRESULT\n" );

		for (wordlength=CORE_minlength;wordlength<CORE_maxlength;wordlength++){
			maxcombination=1;
			for (j=0;j<wordlength;j++)
				maxcombination*= strlen(CORE_charset);
			if (restore-maxcombination>0){
				restore-=maxcombination;
				count+=maxcombination;
			}else
				break;
		}
		if(restore<0){
			printf("Bad arguments\n");
			exit(0);
		}
		CORE_minlength=wordlength;
		count+=restore;
		
		
		for ( wordlength=CORE_minlength; wordlength <  CORE_maxlength && status==0; wordlength++) {
			maxcombination=1;
			for (j=0;j<wordlength;j++)
				maxcombination*= strlen(CORE_charset);
			
			if(wordlength==CORE_minlength)
				iblock=restore;
			else
				iblock=0;

			for (;iblock<maxcombination && status==0;iblock+=1){
				computePwd (iblock, maxcombination, strlen(CORE_charset),CORE_charset, wordlength, word);
				word[wordlength]='\0';
				value=cpu_Core_charset ( CORE_encryptionAlgorithm,header, CORE_charset, word,  wordlength,CORE_keyDerivationFunction, CORE_prefix);

				if (value==1)
					status=1;
				if (CORE_verbose){
					printf("%llu\t",count);
					if (CORE_prefix!=NULL)
						for (j=0;j<strlen(CORE_prefix);j++)
							printf("%c",CORE_prefix[j]);
					for (j=0;j<wordlength;j++)
						printf("%c",word[j]);
					printf("\t");
					if (wordlength<=8)		
						printf("\t");
					if (value==1) {
						printf("YES\n");
					}else{
						printf("NO\n");
					}
				}
				count++;
			}
		}
		wordlength--;
		iblock--;

		if (status==1) {
			uint64_t l,k;
			maxcombination=1;
			for (l=0;l<wordlength;l++)
				maxcombination*=strlen(CORE_charset);
			password_size=wordlength;
			computePwd (iblock, maxcombination, strlen(CORE_charset),CORE_charset, password_size, password);
			password[password_size]='\0';
			if(CORE_prefix!=NULL){
				char tmp[MAXWORDSIZE];
				strncpy(tmp,password,password_size);
				strncpy(password,CORE_prefix,strlen(CORE_prefix));
				strncpy(password+strlen(CORE_prefix),tmp,password_size);
				password_size=strlen(password);
			}	
		} 
	}
#endif

