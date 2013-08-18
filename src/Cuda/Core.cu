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

#include "Tcdefs.h"
#include "Volumes.cuh"
#include <stdio.h>
#include <memory.h>
#include "Crypto.cuh"
#include "Core.cuh"
#include "Pkcs5.cuh"
#include "Xts.cuh"

__device__ __constant__ unsigned char cHeaderEncrypted[TC_VOLUME_HEADER_EFFECTIVE_SIZE];
__device__ __constant__ unsigned char cSalt[SALT_LENGTH];

#define MAXPKCS5OUTSIZE 64

/* The max number of block grid; number of max parallel gpu blocks. */
int blockGridSizeMax;

/* The number of the current block grid; number of current parallel gpu blocks. */
int blockGridSizeCurrent;


/* Pointer of structures to pass to Cuda Kernel. */
unsigned char *dev_salt, *dev_blockPwd, *dev_header, *dev_headerKey;
int *dev_blockPwd_init, *dev_blockPwd_length;
short int *dev_result;
/* With Stream
#define NSTREAM 6
unsigned char *dev_salt, *dev_blockPwd[NSTREAM], *dev_header, *dev_headerKey[NSTREAM];
int *dev_blockPwd_init[NSTREAM], *dev_blockPwd_length[NSTREAM];
short int *dev_result;
*/

int getMultiprocessorCount (void){
	cudaDeviceProp prop;
	cudaGetDeviceProperties(&prop,0);
	return prop.multiProcessorCount;
}

//#define RESIDENTTHREADS		1536
//#define NUMBLOCKS		12
#define NUMTHREADSXBLOCK	256

static void HandleError( cudaError_t err, const char *file,  int line ) {
        if (err != cudaSuccess) {
                printf( "%s in %s at line %d\n", cudaGetErrorString( err ),  file, line );
                exit( EXIT_FAILURE );
        }
}
#define HANDLE_ERROR( err ) (HandleError( err, __FILE__, __LINE__ ))

/*
 __global__ void cuda_Kernel_charset (
    	unsigned char *salt,
    	unsigned char *headerEncrypted,
    	unsigned short int charset_length,
    	unsigned char *charset,
    	unsigned short int password_length,
    	uint64_t maxcombination,
    	 short int *result, 
	 int keyDerivationFunction)
 {
	uint64_t numData = blockIdx.x*blockDim.x+threadIdx.x;
	__align__(8) unsigned char headerkey[192];
	__align__(8) unsigned char headerDecrypted[512];
	__align__(8) unsigned char pwd[8];

	//__device__ void computePwd (int number, int maxcombination, int charsetlength, unsigned char *charset, int wordlength, unsigned char *word){
	computePwd(numData,maxcombination,charset_length,charset,password_length,pwd);
	pwd[password_length]='\0';
	
	//__device__ void cuda_Pbkdf2_charset_ ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey) {
//	cuda_Pbkdf2 ( salt, pwd, password_length, headerkey);

	int value=cuda_Xts (headerEncrypted, headerkey, headerDecrypted);
	if (value==SUCCESS)
		result[numData]=MATCH;
	else
		result[numData]=NOMATCH;
}*/

/*	
__global__ void cuda_Kernel ( unsigned char *salt, unsigned char *headerEncrypted, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int max, int keyDerivationFunction) {
	int value;
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;

	if (numData>=max) return;

	// Array of unsigned char in the shared memory
	__align__(8) unsigned char headerKey[192];
	__align__(8) unsigned char headerDecrypted[512];

	// Calculate the hash header key
	unsigned char *pwd=blockPwd+blockPwd_init[numData];
	int pwd_len = blockPwd_length[numData];


	if(keyDerivationFunction==RIPEMD160)
		cuda_Pbkdf2 ( salt, pwd, pwd_len, headerKey);
	else if(keyDerivationFunction==SHA512)
		cuda_derive_key_sha512 (  pwd, pwd_len, salt, PKCS5_SALT_SIZE, 1000, headerKey, 64);
	else if(keyDerivationFunction==WHIRLPOOL)
		cuda_derive_key_whirlpool (  pwd, pwd_len, salt, PKCS5_SALT_SIZE, 1000, headerKey, 64);
	else
		;
	
	// Decrypt the header and compare the key
	value=cuda_Xts (headerEncrypted, headerKey,headerDecrypted);

	if (value==SUCCESS)
		result[numData]=MATCH;
	else
		result[numData]=NOMATCH;
}
*/


__global__ void cuKernel_generate(unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, int offset, uint32_t maxsize, int charsetlength, unsigned char *charset, int wordlength){
    int number=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
    if (number>=maxsize) {blockPwd_init[number]=1;return;}
	
    blockPwd_init[number]=number*wordlength;//(number==0)?0:blockPwd_init[number-1]+wordlength;
    blockPwd_length[number]=wordlength;
    
    unsigned char *word; word= &blockPwd[number*wordlength];
    unsigned short i=0;
    for (i=0;i<wordlength;i++)
        word[i]=0;
    i=0;
    number+=offset;
    while(number>0){
        word[i]=number%charsetlength;
        number=(number-word[i])/charsetlength;
        i++;
    }
    
    for (i=0;i<wordlength;i++)
    	word[i]=charset[word[i]];
}


__global__ void cuKernel_ripemd160 (unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, unsigned char *headerKey, int max) {
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
	if (numData>=max) return;
	cuda_derive_key_ripemd160 (  blockPwd+blockPwd_init[numData], blockPwd_length[numData], cSalt, PKCS5_SALT_SIZE, 2000, headerKey+numData*MAXPKCS5OUTSIZE, 64);
}
__global__ void cuKernel_sha512 ( unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, unsigned char *headerKey, int max) {
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
	if (numData>=max) return;
	cuda_derive_key_sha512 (  blockPwd+blockPwd_init[numData], blockPwd_length[numData], cSalt, PKCS5_SALT_SIZE, 1000, headerKey+numData*MAXPKCS5OUTSIZE, 64);
}

__global__ void cuKernel_whirlpool ( unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, unsigned char *headerKey, int max) {
       int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
        if (numData>=max) return;
        cuda_derive_key_whirlpool (  blockPwd+blockPwd_init[numData], blockPwd_length[numData], cSalt, PKCS5_SALT_SIZE, 1000, headerKey+numData*MAXPKCS5OUTSIZE, 64);
}

__global__ void cuKernel_aes (unsigned char *headerDecrypted, unsigned char *headerKey, short int *result, int max) {
	int value;
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
	if (numData>=max) return;
	//__align__(8) unsigned char headerDecrypted[512];
	result[numData]=cuXts (AES,cHeaderEncrypted, headerKey+numData*MAXPKCS5OUTSIZE,headerDecrypted);
}
/*
__global__ void cuKernel_serpent (unsigned char *headerDecrypted, unsigned char *headerKey, short int *result, int max) {
	int value;
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
	if (numData>=max) return;
	//__align__(8) unsigned char headerDecrypted[512];
	result[numData]=cuXts (SERPENT,cHeaderEncrypted, headerKey+numData*MAXPKCS5OUTSIZE,headerDecrypted);
}
__global__ void cuKernel_twofish(unsigned char *headerKey, short int *result, int max) {
	int value;
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;
	if (numData>=max) return;
	__align__(8) unsigned char headerDecrypted[512];
	result[numData]=cuXts (TWOFISH,cHeaderEncrypted, headerKey+numData*MAXPKCS5OUTSIZE,headerDecrypted);
}
*/
/*
void cuda_Core_dictionary ( int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int keyDerivationFunction) {

	int size_block=block_currentsize;
	int size_stream=block_currentsize/NSTREAM;
	
	int numBlocks=size_stream/NUMTHREADSXBLOCK+1;
	int numThread=NUMTHREADSXBLOCK;
	if (size_stream<NUMTHREADSXBLOCK)
		numThread=size_stream;

	cudaStream_t stream[NSTREAM];
	for (int i = 0; i < NSTREAM; ++i)
		cudaStreamCreate(&stream[i]);
	
	int lengthpwd[NSTREAM]={0};
	for (int i=0;i<NSTREAM;i++){
	  for (int j=0;j<size_stream;j++) {
		lengthpwd[i]+=blockPwd_length[j+i*size_stream];
	  }
	}
	printf("1-%d 2-%d \n",lengthpwd[0],lengthpwd[1]);
	
	cudaMalloc ( &dev_result, size_block* sizeof(short int)) ;
	cudaMemcpy ( dev_result, result, size_block* sizeof(short int),cudaMemcpyHostToDevice);
	
	unsigned char *host_blockPwd[NSTREAM];
	int *host_blockPwd_init[NSTREAM];
	int *host_blockPwd_length[NSTREAM];
	short int *host_result[NSTREAM];
	
	for (int i =0; i<NSTREAM; i++){
	
		cudaMalloc ( (void **)&dev_blockPwd[i], 	size_stream * PASSWORD_MAXSIZE * sizeof(unsigned char)) ;
		cudaMalloc ( (void **)&dev_blockPwd_init[i], 	size_stream * sizeof(int)) ;
		cudaMalloc ( (void **)&dev_blockPwd_length[i], 	size_stream * sizeof(int)) ;
		cudaMalloc ( (void **)&dev_headerKey[i], 	256 * size_stream * sizeof(unsigned char)) ;
	
	        cudaHostAlloc(&host_blockPwd[i], 	lengthpwd[i]* sizeof(unsigned char), 	cudaHostAllocDefault);
		cudaHostAlloc(&host_blockPwd_init[i], 	size_stream * sizeof(int), 		cudaHostAllocDefault);
		cudaHostAlloc(&host_blockPwd_length[i], size_stream * sizeof(int),	 	cudaHostAllocDefault);
		cudaHostAlloc(&host_result[i], 		size_stream * sizeof(int),	 	cudaHostAllocDefault);
	
		memcpy(host_blockPwd[i], 	blockPwd+((i==0)?0:lengthpwd[i-1]),	lengthpwd[i]*sizeof(unsigned char));
		memcpy(host_blockPwd_init[i], 	blockPwd_init+i*size_stream, 		size_stream*sizeof(int));
		memcpy(host_blockPwd_length[i], blockPwd_length+i*size_stream, 		size_stream*sizeof(int));
			
	}
	
	for (int i = 0; i < NSTREAM; i++){
	  
		cudaMemcpyAsync(dev_blockPwd[i], 	host_blockPwd[i],		lengthpwd[i] * sizeof(unsigned char) , cudaMemcpyHostToDevice, stream[i]) ;
		cudaMemcpyAsync(dev_blockPwd_init[i], 	host_blockPwd_init[i], 		size_stream * sizeof(int) , cudaMemcpyHostToDevice,stream[i]);
		cudaMemcpyAsync(dev_blockPwd_length[i],	host_blockPwd_length[i], 	size_stream * sizeof(int) , cudaMemcpyHostToDevice,stream[i]) ;
		cudaMemcpyAsync(dev_result, 		host_result[0], 		size_stream * sizeof(short int) , cudaMemcpyHostToDevice,stream[0]) ;
		
		
		cuda_Kernel_ripemd160<<<numBlocks,numThread, 0, stream[i]>>>(dev_blockPwd[i], dev_blockPwd_init[i], dev_blockPwd_length[i], dev_headerKey[i], size_stream);
		cuda_Kernel_aes<<<numBlocks,numThread, 0, stream[i]>>>(dev_headerKey[i], dev_result, size_stream);
			
		cudaError_t err=cudaMemcpy(result+i*size_stream, dev_result,	size_stream* sizeof(short int) , cudaMemcpyDeviceToHost) ;
	//	cudaError_t err=cudaMemcpyAsync(host_result[0], dev_result,	size_stream* sizeof(short int) , cudaMemcpyDeviceToHost,stream[0]) ;
		if (err!=cudaSuccess){
			printf("->%s in %s at line %d\n",cudaGetErrorString(err),__FILE__,__LINE__);
		}printf("ok %d\n",i);
		cudaThreadSynchronize();
//	memcpy(result, 	host_result[0], 		size_stream*sizeof(int));
	
	
		
		//cuda_Kernel_ripemd160<<<numBlocks,numThread, 0, stream[i]>>>(dev_blockPwd+ i * size_stream, dev_blockPwd_init+ i * size_stream, dev_blockPwd_length+ i * size_stream, dev_headerKey, size_stream);
		//cuda_Kernel_aes<<<numBlocks,numThread, 0, stream[i]>>>(dev_headerKey, dev_result+ i * size_stream, size_stream);
		
		
		//cudaError_t err=cudaMemcpyAsync(host_result+i*size_stream, 	dev_result+i*size_stream,	size_stream* sizeof(short int) , cudaMemcpyDeviceToHost, stream[i]) ;
		
	}
	
	for (int i = 0; i < NSTREAM; i++)
		cudaStreamDestroy(stream[i]);
    
    
	cudaFree(dev_result);
}
*/

float cuda_Core_dictionary ( int encryptionAlgorithm, int bsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int keyDerivationFunction) {
	int lengthpwd=0;
	for (int j=0;j<bsize;j++) {
		lengthpwd+=blockPwd_length[j];
		result[j]=0;
	}
	
	HANDLE_ERROR(cudaMemcpy(dev_blockPwd, 		blockPwd, 	lengthpwd * sizeof(unsigned char) , cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpy(dev_blockPwd_init, 	blockPwd_init, 	bsize * sizeof(int) , cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpy(dev_blockPwd_length, 	blockPwd_length,bsize * sizeof(int) , cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpy(dev_result, 		result,		bsize * sizeof(short int) , cudaMemcpyHostToDevice));

	int numBlocks=bsize/NUMTHREADSXBLOCK+1;
	int numThreads=NUMTHREADSXBLOCK;
	if (bsize<NUMTHREADSXBLOCK)
		numThreads=bsize;

	cudaEvent_t tstart,tstop;
	float time;
	cudaEventCreate(&tstart);
	cudaEventCreate(&tstop);
	cudaEventRecord(tstart, 0);

	switch(keyDerivationFunction){
		case RIPEMD160:
			cuKernel_ripemd160 <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey, bsize);
			break;
		case SHA512:
			cuKernel_sha512 <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey,bsize);
			break;
		case WHIRLPOOL:
			cuKernel_whirlpool <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey,bsize);
			break;
	}
	
	unsigned char headerKey[50000]={0};
	HANDLE_ERROR(cudaMemcpy(headerKey, dev_headerKey,MAXPKCS5OUTSIZE * bsize * sizeof(unsigned char) , cudaMemcpyDeviceToHost));
	for (int i=0;i<MAXPKCS5OUTSIZE * bsize * sizeof(unsigned char);i++)
		printf("%02x",headerKey[i]);
	printf(" -> ");
		
	unsigned char headerDecrypted[512];
	for (int k=0;k<512;k++)
		headerDecrypted[k]=0;
	unsigned char* dev_headerDecrypted;
	HANDLE_ERROR(cudaMalloc((void **)&dev_headerDecrypted, 512*bsize*sizeof(unsigned char)));
	HANDLE_ERROR(cudaMemcpy(dev_headerDecrypted, headerDecrypted, 512*bsize*sizeof(unsigned char), cudaMemcpyHostToDevice));
	
	
	switch(encryptionAlgorithm){
		case AES:
			cuKernel_aes<<<numBlocks,numThreads>>>(dev_headerDecrypted,dev_headerKey, dev_result, bsize);
			break;
		case SERPENT:
			//cuKernel_serpent<<<numBlocks,numThreads>>>(dev_headerDecrypted,dev_headerKey, dev_result, bsize);
			break;
		case TWOFISH:
			//cuKernel_twofish<<<numBlocks,numThreads>>>(dev_headerKey, dev_result, bsize);
			break;
	}


	cudaEventRecord(tstop, 0);
	cudaEventSynchronize(tstop);
	cudaEventElapsedTime(&time, tstart, tstop);

	HANDLE_ERROR(cudaMemcpy(result, dev_result,bsize* sizeof(short int) , cudaMemcpyDeviceToHost));
	HANDLE_ERROR(cudaMemcpy(headerDecrypted, dev_headerDecrypted,512*bsize* sizeof(unsigned char) , cudaMemcpyDeviceToHost));
	
	for (int i=0;i< 512*bsize;i++)
		printf("%02x",headerDecrypted[i]);
	printf(" ->");
	
	for (int i=0;i< bsize;i++)
		printf("%d",result[i]);
	printf("\n");
	
	return time;
}


float cuda_Core_charset ( int encryptionAlgorithm, uint64_t bsize, uint64_t start, unsigned short int charset_length, unsigned char *charset, unsigned short int password_length, short int *result, int keyDerivationFunction)
{
	int numBlocks=(int)(bsize/NUMTHREADSXBLOCK)+1;
	int numThreads=NUMTHREADSXBLOCK;
	if (bsize<NUMTHREADSXBLOCK)
		numThreads=(int)bsize;
	
	unsigned char *dev_charset = NULL;
	HANDLE_ERROR(cudaMalloc((void **)&dev_charset, charset_length*sizeof(unsigned char)));
	HANDLE_ERROR(cudaMemcpy(dev_charset, charset, charset_length*sizeof(unsigned char), cudaMemcpyHostToDevice));
	/*
	char host_blockPwd[bsize*PASSWORD_MAXSIZE];
	int host_blockPwd_init[bsize];
	int host_blockPwd_length[bsize];
	*/
        cudaEvent_t tstart,tstop;
        float time;
        cudaEventCreate(&tstart);
        cudaEventCreate(&tstop);
        cudaEventRecord(tstart, 0); 	

	cuKernel_generate <<<numBlocks,numThreads>>>(dev_blockPwd,dev_blockPwd_init,dev_blockPwd_length,(int)start,bsize,charset_length,dev_charset,password_length);
	
	
	switch(keyDerivationFunction){
		case RIPEMD160:
			cuKernel_ripemd160 <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey, bsize);
			break;
		case SHA512:
			cuKernel_sha512 <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey,bsize);
			break;
		case WHIRLPOOL:
			cuKernel_whirlpool <<<numBlocks,numThreads>>>(dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_headerKey,bsize);
			break;
	}
	
	switch(encryptionAlgorithm){
		case AES:
			//cuKernel_aes<<<numBlocks,numThreads>>>(dev_headerKey, dev_result, bsize);
			break;
		case SERPENT:
			//cuKernel_serpent<<<numBlocks,numThreads>>>(dev_headerKey, dev_result, bsize);
			break;
		case TWOFISH:
			//cuKernel_twofish<<<numBlocks,numThreads>>>(dev_headerKey, dev_result, bsize);
			break;
	}
	
        cudaEventRecord(tstop, 0);
        cudaEventSynchronize(tstop);
        cudaEventElapsedTime(&time, tstart, tstop);
	/*
	HANDLE_ERROR( cudaMemcpy(host_blockPwd, dev_blockPwd, bsize*PASSWORD_MAXSIZE*sizeof(unsigned char), cudaMemcpyDeviceToHost));
	HANDLE_ERROR( cudaMemcpy(host_blockPwd_init, dev_blockPwd_init, bsize*sizeof(int), cudaMemcpyDeviceToHost));
	HANDLE_ERROR( cudaMemcpy(host_blockPwd_length, dev_blockPwd_length, bsize*sizeof(int), cudaMemcpyDeviceToHost));
	printf("host_blockPwd_init: ");
	for (int i=0;i<bsize;i++)
	  printf("%d",host_blockPwd_init[i]);
	printf("\nhost_blockPwd_length: ");
	for (int i=0;i<bsize;i++)
	  printf("%d",host_blockPwd_length[i]);
	printf("\nhost_blockPwd: ");	
	for (int i=0;i<bsize*PASSWORD_MAXSIZE;i++)
	  printf("%c",host_blockPwd[i]);
	printf("\n");
	*/
	HANDLE_ERROR( cudaMemcpy(result, dev_result, bsize*sizeof(short int), cudaMemcpyDeviceToHost));
	HANDLE_ERROR(cudaFree(dev_charset));
	return time;
}
   

void cuda_Init (int bsize, unsigned char *salt, unsigned char *header) {
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_blockPwd, 		bsize*PASSWORD_MAXSIZE* sizeof(unsigned char))) ;
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_blockPwd_init,		bsize * sizeof(int))) ;
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_blockPwd_length, 	bsize * sizeof(int))) ;
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_headerKey, 		MAXPKCS5OUTSIZE * bsize * sizeof(unsigned char))) ;
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_result, 		bsize * sizeof(short int)))  ;
	HANDLE_ERROR(cudaMemcpyToSymbol( cSalt, 		salt , SALT_LENGTH* sizeof(unsigned char),0,cudaMemcpyHostToDevice)) ;
	HANDLE_ERROR(cudaMemcpyToSymbol( cHeaderEncrypted, 	header , TC_VOLUME_HEADER_EFFECTIVE_SIZE* sizeof(unsigned char),0,cudaMemcpyHostToDevice)) ;
  
}

void cuda_Free(void) {
	cudaFree(dev_salt);
	cudaFree(dev_blockPwd);
	cudaFree(dev_blockPwd_init);
	cudaFree(dev_blockPwd_length);
	cudaFree(dev_result);
	cudaFree(dev_headerKey);
		
	cudaDeviceReset();

}
