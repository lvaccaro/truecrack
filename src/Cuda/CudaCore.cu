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
#include "Volumes.h"
#include <stdio.h>
#include <memory.h>
#include "Crypto.h"
#include "CudaCore.cuh"
#include "CudaPkcs5.cuh"
#include "CudaXts.cuh"



/* The max number of block grid; number of max parallel gpu blocks. */
int blockGridSizeMax;

/* The number of the current block grid; number of current parallel gpu blocks. */
int blockGridSizeCurrent;

/* Pointer of structures to pass to Cuda Kernel. */
unsigned char *dev_salt, *dev_blockPwd, *dev_header;
int *dev_blockPwd_init, *dev_blockPwd_length;
short int *dev_result;


int getMultiprocessorCount (void){
	cudaDeviceProp prop;
	cudaGetDeviceProperties(&prop,0);
	return prop.multiProcessorCount;
}

//#define RESIDENTTHREADS		1536
//#define NUMBLOCKS		12
#define NUMTHREADSXBLOCK	128

static void HandleError( cudaError_t err, const char *file,  int line ) {
        if (err != cudaSuccess) {
                printf( "%s in %s at line %d\n", cudaGetErrorString( err ),  file, line );
                exit( EXIT_FAILURE );
        }
}
#define HANDLE_ERROR( err ) (HandleError( err, __FILE__, __LINE__ ))


__device__ void computePwd (int number, int maxcombination, int charsetlength, unsigned char *charset, int wordlength, unsigned char *word){
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
__device__ void cuda_Pbkdf2_charset ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey, int numBlock) {
	SupportPkcs5 support;
	SupportPkcs5 *sup;
	sup = &support;
	
	//INCLUDE: void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b)

	int c, i;	
	int b=numBlock;
	unsigned char *u=headerkey+RIPEMD160_DIGESTSIZE*b;

	// iteration 1 
	memset (sup->ccounter, 0, 4);
	sup->ccounter[3] = (char) b;
	memcpy (sup->cinit, salt, SALT_LENGTH);	// salt 
	memcpy (&sup->cinit[SALT_LENGTH],sup->ccounter, 4);	// big-endian block number 
	
	cuda_hmac_ripemd160 (pwd, pwd_len, sup->cinit, SALT_LENGTH + 4, sup->cj, sup);
	memcpy (u, sup->cj, RIPEMD160_DIGESTSIZE);
	
	//remaining iterations 
	for (c = 1; c < ITERATIONS; c++)
	{
		cuda_hmac_ripemd160 (pwd, pwd_len, sup->cj, RIPEMD160_DIGESTSIZE, sup->ck,sup);
		for (i = 0; i < RIPEMD160_DIGESTSIZE; i++)
		{
			u[i] ^= sup->ck[i];
			sup->cj[i] = sup->ck[i];
		}
	}
}

 __global__ void cuda_Kernel_charset (
    	unsigned char *salt,
    	unsigned char *headerEncrypted,
    	unsigned short int charset_length,
    	unsigned char *charset,
    	unsigned short int password_length,
    	unsigned short int maxcombination,
    	 short int *result)
 {
	int numData = blockIdx.x*blockDim.x+threadIdx.x;
	__align__(8) unsigned char headerkey[192];
	__align__(8) unsigned char headerDecrypted[512];
	__align__(8) unsigned char pwd[8];

	//__device__ void computePwd (int number, int maxcombination, int charsetlength, unsigned char *charset, int wordlength, unsigned char *word){
	computePwd(numData,maxcombination,charset_length,charset,password_length,pwd);
	pwd[password_length]='\0';
	
	//__device__ void cuda_Pbkdf2_charset_ ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey) {
	cuda_Pbkdf2_charset_ ( salt, pwd, password_length, headerkey);

	int value=cuda_Xts (headerEncrypted, headerkey, headerDecrypted);
	if (value==SUCCESS)
		result[numData]=MATCH;
	else
		result[numData]=NOMATCH;
}

__global__ void cuda_Kernel ( unsigned char *salt, unsigned char *headerEncrypted, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int max) {
	int value;
	int numData=blockIdx.x*NUMTHREADSXBLOCK+threadIdx.x;

	if (numData>=max) return;

	// Array of unsigned char in the shared memory
	__align__(8) unsigned char headerkey[192];
	__align__(8) unsigned char headerDecrypted[512];

	// Calculate the hash header key
	int i=0;
	for (i=0;i<10;i++)
		cuda_Pbkdf2 (salt, blockPwd, blockPwd_init, blockPwd_length, headerkey, numData,i);


	// Decrypt the header and compare the key
	value=cuda_Xts (headerEncrypted, headerkey,headerDecrypted);

	if (value==SUCCESS)
		result[numData]=MATCH;
	else
		result[numData]=NOMATCH;
}

/*
__global__ void cuda_Kernel ( unsigned char *salt, unsigned char *headerEncrypted, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result, int max) {
	int value;
	int numData=blockIdx.x;//threadIdx.x;

	if (numData>=max) return;

	// Array of unsigned char in the shared memory
	__shared__ __align__(8) unsigned char headerkey[192];
	__shared__ __align__(8) unsigned char headerDecrypted[512];

	// Calculate the hash header key
	int i=0;
	//for (i=0;i<10;i++)
		cuda_Pbkdf2 (salt, blockPwd, blockPwd_init, blockPwd_length, headerkey, blockIdx.x,threadIdx.x);

	__syncthreads();

if(threadIdx.x==0){
	// Decrypt the header and compare the key
	value=cuda_Xts (headerEncrypted, headerkey,headerDecrypted);

	if (value==SUCCESS)
		result[numData]=MATCH;
	else
		result[numData]=NOMATCH;
}
}
*/
/*
void cuda_Core ( int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result) {	
	cudaStream_t stream[2];
	for (int i = 0; i < 2; ++i)
	    cudaStreamCreate(&stream[i]);

	int lengthpwd=0;
	for (int j=0;j<block_currentsize;j++) {
		lengthpwd+=blockPwd_length[j];
	}

	cudaMalloc ( &dev_result, block_currentsize * sizeof(short int)) ;

	unsigned char *host_blockPwd;
	int *host_blockPwd_init, *host_blockPwd_length;
	short int *host_result;
	cudaHostAlloc( (void**) &host_blockPwd, lengthpwd *sizeof(unsigned char),cudaHostAllocDefault );
	cudaHostAlloc( (void**) &host_blockPwd_init, block_currentsize *sizeof(int),cudaHostAllocDefault );
	cudaHostAlloc( (void**) &host_blockPwd_length, block_currentsize *sizeof(int),cudaHostAllocDefault );
	cudaHostAlloc( (void**) &host_result, block_currentsize *sizeof(short int),cudaHostAllocDefault );

	for (int i=0;i<block_currentsize;i++){
		host_blockPwd_init[i]=blockPwd_init[i];
		host_blockPwd_length[i]=blockPwd_length[i];
		host_result[i]=result[i];
	}
	for (int i=0;i<lengthpwd;i++)
		host_blockPwd[i]=blockPwd[i];

	int i;
	for (i=0;i<block_currentsize;i++) {
		result[i]=NODEFINED;
	}
	
#define STREAM 1
int sizePwd=block_currentsize;
int sizeStream=sizePwd/STREAM;
int lenghtPwdInStream[STREAM];


	int numBlocks=sizeStream/NUMTHREADSXBLOCK+1;
	int numThread=NUMTHREADSXBLOCK;
	if (sizeStream<NUMTHREADSXBLOCK)
		numThread=sizeStream;

	for (i = 0; i < STREAM; ++i) {
	    lenghtPwdInStream[i]=0;
	    for (int j=i*sizeStream;j<sizeStream;j++) {
		lenghtPwdInStream[i]+=blockPwd_length[j];
	    }
	}
int j;	
	for (i = 0; i < STREAM; ++i) {
	    cudaMemcpyAsync(dev_blockPwd_init+i*sizeStream, host_blockPwd_init+i*sizeStream, sizeStream* sizeof(int) , cudaMemcpyHostToDevice,stream[i]);
	    cudaMemcpyAsync(dev_blockPwd_length+i*sizeStream, host_blockPwd_length+i*sizeStream, sizeStream * sizeof(int) , cudaMemcpyHostToDevice,stream[i]) ;
	    cudaMemcpyAsync(dev_result+i*sizeStream, host_result+i*sizeStream, sizeStream * sizeof(short int) , cudaMemcpyHostToDevice,stream[i]) ;
	    cudaMemcpyAsync(dev_blockPwd+i*lenghtPwdInStream[i-1], host_blockPwd+i*lenghtPwdInStream[i-1], lenghtPwdInStream[i] * sizeof(unsigned char), cudaMemcpyHostToDevice,stream[i]) ;
	    
	    printf("start: %s\n",host_blockPwd+i*lenghtPwdInStream[i-1]);
	    printf("%d : %d - %d \n",sizeStream,numBlocks,numThread);

	    
	    cuda_Kernel<<<numBlocks,numThread,0,stream[i]>>>(dev_salt, dev_header, dev_blockPwd+i*lenghtPwdInStream[i-1], dev_blockPwd_init+i*sizeStream, dev_blockPwd_length+i*sizeStream, dev_result+i*sizeStream,sizeStream);
	    
	    
	    cudaError_t err=cudaMemcpyAsync(host_result+i*sizeStream, dev_result+i*sizeStream,sizeStream * sizeof(short int) , cudaMemcpyDeviceToHost,stream[i]) ;
	    if (err!=cudaSuccess){
		  printf("->%s in %s at line %d\n",cudaGetErrorString(err),__FILE__,__LINE__);
	    }
   //  cudaMemcpyAsync(hostPtr + i * size, outputDevPtr + i * size,       size, cudaMemcpyDeviceToHost, stream[i]);

	    cudaMemcpyAsync(inputDevPtr + i * size, hostPtr + i * size,
			    size, cudaMemcpyHostToDevice, stream[i]);
	    
	    MyKernel <<<100, 512, 0, stream[i]>>>
		  (outputDevPtr + i * size, inputDevPtr + i * size, size);
	    cudaMemcpyAsync(hostPtr + i * size, outputDevPtr + i * size,
			    size, cudaMemcpyDeviceToHost, stream[i]);
	}

	
	cudaStreamSynchronize(stream[0]);
	cudaStreamSynchronize(stream[1]);

	for (i=0;i<STREAM;i++)
	    for (j=0;j<sizeStream;j++)
		printf("%d -> %c\n",j+i*sizeStream,result[j+i*sizeStream]);
	
	for (int i = 0; i < STREAM; ++i)
	    cudaStreamDestroy(stream[i]);
}
*/

void cuda_Core_dictionary ( int block_currentsize, unsigned char *blockPwd, int *blockPwd_init, int *blockPwd_length, short int *result) {

	int lengthpwd=0;
	for (int j=0;j<block_currentsize;j++) {
		lengthpwd+=blockPwd_length[j];
		result[j]=0;
	}
	cudaMalloc ( &dev_result, block_currentsize * sizeof(short int)) ;
	cudaMemcpy(dev_blockPwd, blockPwd, lengthpwd * sizeof(unsigned char) , cudaMemcpyHostToDevice) ;
	cudaMemcpy(dev_blockPwd_init, blockPwd_init, block_currentsize * sizeof(int) , cudaMemcpyHostToDevice);
	cudaMemcpy(dev_blockPwd_length, blockPwd_length, block_currentsize * sizeof(int) , cudaMemcpyHostToDevice) ;
	cudaMemcpy(dev_result, result, block_currentsize * sizeof(short int) , cudaMemcpyHostToDevice) ;

	int numBlocks=block_currentsize/NUMTHREADSXBLOCK+1;
	int numThread=NUMTHREADSXBLOCK;
	if (block_currentsize<NUMTHREADSXBLOCK)
		numThread=block_currentsize;

	cuda_Kernel<<<numBlocks,numThread>>>(dev_salt, dev_header, dev_blockPwd, dev_blockPwd_init, dev_blockPwd_length, dev_result,block_currentsize);

	cudaError_t err=cudaMemcpy(result, dev_result,block_currentsize* sizeof(short int) , cudaMemcpyDeviceToHost) ;
	if (err!=cudaSuccess){
		printf("->%s in %s at line %d\n",cudaGetErrorString(err),__FILE__,__LINE__);
	}
	cudaFree(dev_result);
}

void cuda_Core_charset ( unsigned short int charset_length, unsigned char *charset, unsigned short int password_length, short int *result) 
{
	uint64_t maxcombination=1;
	for (int i=0;i<password_length;i++)
		maxcombination*=charset_length;

	unsigned char *dev_charset = NULL;
	HANDLE_ERROR(cudaMalloc((void **)&dev_charset, charset_length*sizeof(unsigned char)));
	HANDLE_ERROR(cudaMalloc ( (void **)&dev_result, maxcombination * sizeof(short int))) ;
	HANDLE_ERROR(cudaMemcpy(dev_charset, charset, charset_length*sizeof(unsigned char), cudaMemcpyHostToDevice));
	HANDLE_ERROR(cudaMemcpy(dev_result, result, maxcombination*sizeof(short int), cudaMemcpyHostToDevice));
     
	uint64_t numBlocks=maxcombination/NUMTHREADSXBLOCK+1;
	int numThread=NUMTHREADSXBLOCK;
	if (maxcombination<NUMTHREADSXBLOCK)
		numThread=maxcombination;

	cuda_Kernel_charset<<<numBlocks,numThread>>>(dev_salt, dev_header, charset_length, dev_charset, password_length, maxcombination,dev_result);
	
	// Copy the device result vector in device memory to the host result vector in host memory.
	HANDLE_ERROR( cudaMemcpy(result, dev_result, maxcombination*sizeof(short int), cudaMemcpyDeviceToHost));
	
	HANDLE_ERROR(cudaFree(dev_charset));;
	HANDLE_ERROR(cudaFree(dev_result));;
}

   

void cuda_Init (int block_maxsize, unsigned char *salt, unsigned char *header) {
	blockGridSizeMax=block_maxsize;

	cudaMalloc ( (void **)&dev_blockPwd, blockGridSizeMax * PASSWORD_MAXSIZE * sizeof(unsigned char)) ;
	cudaMalloc ( (void **)&dev_blockPwd_init, blockGridSizeMax * sizeof(int)) ;
	cudaMalloc ( (void **)&dev_blockPwd_length, blockGridSizeMax * sizeof(int)) ;
	cudaMalloc ( (void **)&dev_salt, SALT_LENGTH * sizeof(unsigned char)) ;
	cudaMalloc ( (void **)&dev_header, TC_VOLUME_HEADER_EFFECTIVE_SIZE * sizeof(unsigned char)) ;

	cudaMemcpy(dev_salt, salt, SALT_LENGTH * sizeof(unsigned char) , cudaMemcpyHostToDevice) ;
	cudaMemcpy(dev_header, header, TC_VOLUME_HEADER_EFFECTIVE_SIZE * sizeof(unsigned char) , cudaMemcpyHostToDevice) ;

}

void cuda_Free(void) {
	cudaFree(dev_salt);
	cudaFree(dev_blockPwd);
	cudaFree(dev_blockPwd_init);
	cudaFree(dev_blockPwd_length);
	cudaFree(dev_header);
}
