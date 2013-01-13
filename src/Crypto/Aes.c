/*
 * Copyright (C)  2011  Luca Vaccaro
 * Based on TrueCrypt, freely available at http://www.truecrypt.org/
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
/*
Collection of files for AES encryption algorithm
- Aes.h
- Aesopt.h
- Aestab.h
- Aestab.c
- Aeskey.c
- Aescrypt.c
*/

/*
 * Aes.h
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007

 This file contains the definitions required to use AES in C. See aesopt.h
 for optimisation details.
*/

/* Adapted for TrueCrypt */

#ifndef _AES_H
#define _AES_H

#include "Common/Tcdefs.h"

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS    0
#define EXIT_FAILURE    1
#endif
#define INT_RETURN   int

#if defined(__cplusplus)
extern "C"
{
#endif

// #define AES_128     /* define if AES with 128 bit keys is needed    */
// #define AES_192     /* define if AES with 192 bit keys is needed    */
#define AES_256     /* define if AES with 256 bit keys is needed    */
// #define AES_VAR     /* define if a variable key size is needed      */
// #define AES_MODES   /* define if support is needed for modes        */

    /* The following must also be set in assembler files if being used  */

#define AES_ENCRYPT /* if support for encryption is needed          */
#define AES_DECRYPT /* if support for decryption is needed          */
#define AES_ERR_CHK /* for parameter checks & error return codes    */
#define AES_REV_DKS /* define to reverse decryption key schedule    */

#define AES_BLOCK_SIZE  16  /* the AES block size in bytes          */
#define N_COLS           4  /* the number of columns in the state   */

    /* The key schedule length is 11, 13 or 15 16-byte blocks for 128,  */
    /* 192 or 256-bit keys respectively. That is 176, 208 or 240 bytes  */
    /* or 44, 52 or 60 32-bit words.                                    */

#if defined( AES_VAR ) || defined( AES_256 )
#define KS_LENGTH       60
#elif defined( AES_192 )
#define KS_LENGTH       52
#else
#define KS_LENGTH       44
#endif

#if defined( AES_ERR_CHK )
#define AES_RETURN     INT_RETURN
#else
#define AES_RETURN     VOID_RETURN
#endif

    /* the character array 'inf' in the following structures is used    */
    /* to hold AES context information. This AES code uses cx->inf.b[0] */
    /* to hold the number of rounds multiplied by 16. The other three   */
    /* elements can be used by code that implements additional modes    */

    typedef union
    {   uint_32t l;
        uint_8t b[4];
    } aes_inf;

    typedef struct
    {
        uint_32t ks[KS_LENGTH];
        aes_inf inf;
    } aes_encrypt_ctx;

    typedef struct
    {
        uint_32t ks[KS_LENGTH];
        aes_inf inf;
    } aes_decrypt_ctx;

    /* This routine must be called before first use if non-static       */
    /* tables are being used                                            */

    AES_RETURN aes_init(void);

    /* Key lengths in the range 16 <= key_len <= 32 are given in bytes, */
    /* those in the range 128 <= key_len <= 256 are given in bits       */

#if defined( AES_ENCRYPT )

#if defined(AES_128) || defined(AES_VAR)
    AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
    AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
    AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
    AES_RETURN aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1]);
#endif

    AES_RETURN aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1]);

#endif

#if defined( AES_DECRYPT )

#if defined(AES_128) || defined(AES_VAR)
    AES_RETURN aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_192) || defined(AES_VAR)
    AES_RETURN aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_256) || defined(AES_VAR)
    AES_RETURN aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
#endif

#if defined(AES_VAR)
    AES_RETURN aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1]);
#endif

    AES_RETURN aes_decrypt(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1]);

#endif

#if defined(AES_MODES)

    /* Multiple calls to the following subroutines for multiple block   */
    /* ECB, CBC, CFB, OFB and CTR mode encryption can be used to handle */
    /* long messages incremantally provided that the context AND the iv */
    /* are preserved between all such calls.  For the ECB and CBC modes */
    /* each individual call within a series of incremental calls must   */
    /* process only full blocks (i.e. len must be a multiple of 16) but */
    /* the CFB, OFB and CTR mode calls can handle multiple incremental  */
    /* calls of any length. Each mode is reset when a new AES key is    */
    /* set but ECB and CBC operations can be reset without setting a    */
    /* new key by setting a new IV value.  To reset CFB, OFB and CTR    */
    /* without setting the key, aes_mode_reset() must be called and the */
    /* IV must be set.  NOTE: All these calls update the IV on exit so  */
    /* this has to be reset if a new operation with the same IV as the  */
    /* previous one is required (or decryption follows encryption with  */
    /* the same IV array).                                              */

    AES_RETURN aes_test_alignment_detection(unsigned int n);

    AES_RETURN aes_ecb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, const aes_encrypt_ctx cx[1]);

    AES_RETURN aes_ecb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, const aes_decrypt_ctx cx[1]);

    AES_RETURN aes_cbc_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, unsigned char *iv, const aes_encrypt_ctx cx[1]);

    AES_RETURN aes_cbc_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, unsigned char *iv, const aes_decrypt_ctx cx[1]);

    AES_RETURN aes_mode_reset(aes_encrypt_ctx cx[1]);

    AES_RETURN aes_cfb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

    AES_RETURN aes_cfb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                               int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

#define aes_ofb_encrypt aes_ofb_crypt
#define aes_ofb_decrypt aes_ofb_crypt

    AES_RETURN aes_ofb_crypt(const unsigned char *ibuf, unsigned char *obuf,
                             int len, unsigned char *iv, aes_encrypt_ctx cx[1]);

    typedef void cbuf_inc(unsigned char *cbuf);

#define aes_ctr_encrypt aes_ctr_crypt
#define aes_ctr_decrypt aes_ctr_crypt

    AES_RETURN aes_ctr_crypt(const unsigned char *ibuf, unsigned char *obuf,
                             int len, unsigned char *cbuf, cbuf_inc ctr_inc, aes_encrypt_ctx cx[1]);

#endif

#if defined(__cplusplus)
}
#endif

#endif



/*
 * Aesopt.h
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007

 This file contains the compilation options for AES (Rijndael) and code
 that is common across encryption, key scheduling and table generation.

 OPERATION

 These source code files implement the AES algorithm Rijndael designed by
 Joan Daemen and Vincent Rijmen. This version is designed for the standard
 block size of 16 bytes and for key sizes of 128, 192 and 256 bits (16, 24
 and 32 bytes).

 This version is designed for flexibility and speed using operations on
 32-bit words rather than operations on bytes.  It can be compiled with
 either big or little endian internal byte order but is faster when the
 native byte order for the processor is used.

 THE CIPHER INTERFACE

 The cipher interface is implemented as an array of bytes in which lower
 AES bit sequence indexes map to higher numeric significance within bytes.

  uint_8t                 (an unsigned  8-bit type)
  uint_32t                (an unsigned 32-bit type)
  struct aes_encrypt_ctx  (structure for the cipher encryption context)
  struct aes_decrypt_ctx  (structure for the cipher decryption context)
  AES_RETURN                the function return type

  C subroutine calls:

  AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1]);
  AES_RETURN aes_encrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_encrypt_ctx cx[1]);

  AES_RETURN aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1]);
  AES_RETURN aes_decrypt(const unsigned char *in, unsigned char *out,
                                                  const aes_decrypt_ctx cx[1]);

 IMPORTANT NOTE: If you are using this C interface with dynamic tables make sure that
 you call aes_init() before AES is used so that the tables are initialised.

 C++ aes class subroutines:

     Class AESencrypt  for encryption

      Construtors:
          AESencrypt(void)
          AESencrypt(const unsigned char *key) - 128 bit key
      Members:
          AES_RETURN key128(const unsigned char *key)
          AES_RETURN key192(const unsigned char *key)
          AES_RETURN key256(const unsigned char *key)
          AES_RETURN encrypt(const unsigned char *in, unsigned char *out) const

      Class AESdecrypt  for encryption
      Construtors:
          AESdecrypt(void)
          AESdecrypt(const unsigned char *key) - 128 bit key
      Members:
          AES_RETURN key128(const unsigned char *key)
          AES_RETURN key192(const unsigned char *key)
          AES_RETURN key256(const unsigned char *key)
          AES_RETURN decrypt(const unsigned char *in, unsigned char *out) const
*/

/* Adapted for TrueCrypt */

#if !defined( _AESOPT_H )
#define _AESOPT_H

#ifdef TC_WINDOWS_BOOT
#define ASM_X86_V2
#endif



#include "Common/Endian.h"
#define IS_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define IS_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if BYTE_ORDER == LITTLE_ENDIAN
#  define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#endif

#if BYTE_ORDER == BIG_ENDIAN
#  define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#endif


/*  CONFIGURATION - THE USE OF DEFINES

    Later in this section there are a number of defines that control the
    operation of the code.  In each section, the purpose of each define is
    explained so that the relevant form can be included or excluded by
    setting either 1's or 0's respectively on the branches of the related
    #if clauses.  The following local defines should not be changed.
*/

#define ENCRYPTION_IN_C     1
#define DECRYPTION_IN_C     2
#define ENC_KEYING_IN_C     4
#define DEC_KEYING_IN_C     8

#define NO_TABLES           0
#define ONE_TABLE           1
#define FOUR_TABLES         4
#define NONE                0
#define PARTIAL             1
#define FULL                2

/*  --- START OF USER CONFIGURED OPTIONS --- */

/*  1. BYTE ORDER WITHIN 32 BIT WORDS

    The fundamental data processing units in Rijndael are 8-bit bytes. The
    input, output and key input are all enumerated arrays of bytes in which
    bytes are numbered starting at zero and increasing to one less than the
    number of bytes in the array in question. This enumeration is only used
    for naming bytes and does not imply any adjacency or order relationship
    from one byte to another. When these inputs and outputs are considered
    as bit sequences, bits 8*n to 8*n+7 of the bit sequence are mapped to
    byte[n] with bit 8n+i in the sequence mapped to bit 7-i within the byte.
    In this implementation bits are numbered from 0 to 7 starting at the
    numerically least significant end of each byte (bit n represents 2^n).

    However, Rijndael can be implemented more efficiently using 32-bit
    words by packing bytes into words so that bytes 4*n to 4*n+3 are placed
    into word[n]. While in principle these bytes can be assembled into words
    in any positions, this implementation only supports the two formats in
    which bytes in adjacent positions within words also have adjacent byte
    numbers. This order is called big-endian if the lowest numbered bytes
    in words have the highest numeric significance and little-endian if the
    opposite applies.

    This code can work in either order irrespective of the order used by the
    machine on which it runs. Normally the internal byte order will be set
    to the order of the processor on which the code is to be run but this
    define can be used to reverse this in special situations

    WARNING: Assembler code versions rely on PLATFORM_BYTE_ORDER being set.
    This define will hence be redefined later (in section 4) if necessary
*/

#if 1
#define ALGORITHM_BYTE_ORDER PLATFORM_BYTE_ORDER
#elif 0
#define ALGORITHM_BYTE_ORDER IS_LITTLE_ENDIAN
#elif 0
#define ALGORITHM_BYTE_ORDER IS_BIG_ENDIAN
#else
#error The algorithm byte order is not defined
#endif

/*  2. VIA ACE SUPPORT

    Define this option if support for the VIA ACE is required. This uses
    inline assembler instructions and is only implemented for the Microsoft,
    Intel and GCC compilers.  If VIA ACE is known to be present, then defining
    ASSUME_VIA_ACE_PRESENT will remove the ordinary encryption/decryption
    code.  If USE_VIA_ACE_IF_PRESENT is defined then VIA ACE will be used if
    it is detected (both present and enabled) but the normal AES code will
    also be present.

    When VIA ACE is to be used, all AES encryption contexts MUST be 16 byte
    aligned; other input/output buffers do not need to be 16 byte aligned
    but there are very large performance gains if this can be arranged.
    VIA ACE also requires the decryption key schedule to be in reverse
    order (which later checks below ensure).
*/

#if 0 && !defined( USE_VIA_ACE_IF_PRESENT )
#  define USE_VIA_ACE_IF_PRESENT
#endif

#if 0 && !defined( ASSUME_VIA_ACE_PRESENT )
#  define ASSUME_VIA_ACE_PRESENT
#  endif

#if defined ( _WIN64 ) || defined( _WIN32_WCE ) || \
                    defined( _MSC_VER ) && ( _MSC_VER <= 800 )
#  if defined( USE_VIA_ACE_IF_PRESENT )
#    undef USE_VIA_ACE_IF_PRESENT
#  endif
#  if defined( ASSUME_VIA_ACE_PRESENT )
#    undef ASSUME_VIA_ACE_PRESENT
#  endif
#endif

/*  3. ASSEMBLER SUPPORT

    This define (which can be on the command line) enables the use of the
    assembler code routines for encryption, decryption and key scheduling
    as follows:

    ASM_X86_V1C uses the assembler (aes_x86_v1.asm) with large tables for
                encryption and decryption and but with key scheduling in C
    ASM_X86_V2  uses assembler (aes_x86_v2.asm) with compressed tables for
                encryption, decryption and key scheduling
    ASM_X86_V2C uses assembler (aes_x86_v2.asm) with compressed tables for
                encryption and decryption and but with key scheduling in C
    ASM_AMD64_C uses assembler (aes_amd64.asm) with compressed tables for
                encryption and decryption and but with key scheduling in C

    Change one 'if 0' below to 'if 1' to select the version or define
    as a compilation option.
*/

#if 0 && !defined( ASM_X86_V1C )
#  define ASM_X86_V1C
#elif 0 && !defined( ASM_X86_V2  )
#  define ASM_X86_V2
#elif 0 && !defined( ASM_X86_V2C )
#  define ASM_X86_V2C
#elif 0 && !defined( ASM_AMD64_C )
#  define ASM_AMD64_C
#endif

#if (defined ( ASM_X86_V1C ) || defined( ASM_X86_V2 ) || defined( ASM_X86_V2C )) \
      && !defined( _M_IX86 ) || defined( ASM_AMD64_C ) && !defined( _M_X64 )
//#  error Assembler code is only available for x86 and AMD64 systems
#endif

/*  4. FAST INPUT/OUTPUT OPERATIONS.

    On some machines it is possible to improve speed by transferring the
    bytes in the input and output arrays to and from the internal 32-bit
    variables by addressing these arrays as if they are arrays of 32-bit
    words.  On some machines this will always be possible but there may
    be a large performance penalty if the byte arrays are not aligned on
    the normal word boundaries. On other machines this technique will
    lead to memory access errors when such 32-bit word accesses are not
    properly aligned. The option SAFE_IO avoids such problems but will
    often be slower on those machines that support misaligned access
    (especially so if care is taken to align the input  and output byte
    arrays on 32-bit word boundaries). If SAFE_IO is not defined it is
    assumed that access to byte arrays as if they are arrays of 32-bit
    words will not cause problems when such accesses are misaligned.
*/
#if 1 && !defined( _MSC_VER )
#define SAFE_IO
#endif

/*  5. LOOP UNROLLING

    The code for encryption and decrytpion cycles through a number of rounds
    that can be implemented either in a loop or by expanding the code into a
    long sequence of instructions, the latter producing a larger program but
    one that will often be much faster. The latter is called loop unrolling.
    There are also potential speed advantages in expanding two iterations in
    a loop with half the number of iterations, which is called partial loop
    unrolling.  The following options allow partial or full loop unrolling
    to be set independently for encryption and decryption
*/
#if 1
#define ENC_UNROLL  FULL
#elif 0
#define ENC_UNROLL  PARTIAL
#else
#define ENC_UNROLL  NONE
#endif

#if 1
#define DEC_UNROLL  FULL
#elif 0
#define DEC_UNROLL  PARTIAL
#else
#define DEC_UNROLL  NONE
#endif

/*  6. FAST FINITE FIELD OPERATIONS

    If this section is included, tables are used to provide faster finite
    field arithmetic (this has no effect if FIXED_TABLES is defined).
*/
#if !defined (TC_WINDOWS_BOOT)
#define FF_TABLES
#endif

/*  7. INTERNAL STATE VARIABLE FORMAT

    The internal state of Rijndael is stored in a number of local 32-bit
    word varaibles which can be defined either as an array or as individual
    names variables. Include this section if you want to store these local
    varaibles in arrays. Otherwise individual local variables will be used.
*/
#if 1
#define ARRAYS
#endif

/*  8. FIXED OR DYNAMIC TABLES

    When this section is included the tables used by the code are compiled
    statically into the binary file.  Otherwise the subroutine aes_init()
    must be called to compute them before the code is first used.
*/
#if !defined (TC_WINDOWS_BOOT) && !(defined( _MSC_VER ) && ( _MSC_VER <= 800 ))
#define FIXED_TABLES
#endif

/*  9. TABLE ALIGNMENT

    On some sytsems speed will be improved by aligning the AES large lookup
    tables on particular boundaries. This define should be set to a power of
    two giving the desired alignment. It can be left undefined if alignment
    is not needed.  This option is specific to the Microsft VC++ compiler -
    it seems to sometimes cause trouble for the VC++ version 6 compiler.
*/

#if 1 && defined( _MSC_VER ) && ( _MSC_VER >= 1300 )
#define TABLE_ALIGN 32
#endif

/*  10. TABLE OPTIONS

    This cipher proceeds by repeating in a number of cycles known as 'rounds'
    which are implemented by a round function which can optionally be speeded
    up using tables.  The basic tables are each 256 32-bit words, with either
    one or four tables being required for each round function depending on
    how much speed is required. The encryption and decryption round functions
    are different and the last encryption and decrytpion round functions are
    different again making four different round functions in all.

    This means that:
      1. Normal encryption and decryption rounds can each use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.
      2. The last encryption and decryption rounds can also use either 0, 1
         or 4 tables and table spaces of 0, 1024 or 4096 bytes each.

    Include or exclude the appropriate definitions below to set the number
    of tables used by this implementation.
*/

#if 1   /* set tables for the normal encryption round */
#define ENC_ROUND   FOUR_TABLES
#elif 0
#define ENC_ROUND   ONE_TABLE
#else
#define ENC_ROUND   NO_TABLES
#endif

#if 1   /* set tables for the last encryption round */
#define LAST_ENC_ROUND  FOUR_TABLES
#elif 0
#define LAST_ENC_ROUND  ONE_TABLE
#else
#define LAST_ENC_ROUND  NO_TABLES
#endif

#if 1   /* set tables for the normal decryption round */
#define DEC_ROUND   FOUR_TABLES
#elif 0
#define DEC_ROUND   ONE_TABLE
#else
#define DEC_ROUND   NO_TABLES
#endif

#if 1   /* set tables for the last decryption round */
#define LAST_DEC_ROUND  FOUR_TABLES
#elif 0
#define LAST_DEC_ROUND  ONE_TABLE
#else
#define LAST_DEC_ROUND  NO_TABLES
#endif

/*  The decryption key schedule can be speeded up with tables in the same
    way that the round functions can.  Include or exclude the following
    defines to set this requirement.
*/
#if 1
#define KEY_SCHED   FOUR_TABLES
#elif 0
#define KEY_SCHED   ONE_TABLE
#else
#define KEY_SCHED   NO_TABLES
#endif

/*  ---- END OF USER CONFIGURED OPTIONS ---- */

/* VIA ACE support is only available for VC++ and GCC */

#if !defined( _MSC_VER ) && !defined( __GNUC__ )
#  if defined( ASSUME_VIA_ACE_PRESENT )
#    undef ASSUME_VIA_ACE_PRESENT
#  endif
#  if defined( USE_VIA_ACE_IF_PRESENT )
#    undef USE_VIA_ACE_IF_PRESENT
#  endif
#endif

#if defined( ASSUME_VIA_ACE_PRESENT ) && !defined( USE_VIA_ACE_IF_PRESENT )
#define USE_VIA_ACE_IF_PRESENT
#endif

#if defined( USE_VIA_ACE_IF_PRESENT ) && !defined ( AES_REV_DKS )
#define AES_REV_DKS
#endif

/* Assembler support requires the use of platform byte order */

#if ( defined( ASM_X86_V1C ) || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C ) ) \
    && (ALGORITHM_BYTE_ORDER != PLATFORM_BYTE_ORDER)
#undef  ALGORITHM_BYTE_ORDER
#define ALGORITHM_BYTE_ORDER PLATFORM_BYTE_ORDER
#endif

/* In this implementation the columns of the state array are each held in
   32-bit words. The state array can be held in various ways: in an array
   of words, in a number of individual word variables or in a number of
   processor registers. The following define maps a variable name x and
   a column number c to the way the state array variable is to be held.
   The first define below maps the state into an array x[c] whereas the
   second form maps the state into a number of individual variables x0,
   x1, etc.  Another form could map individual state colums to machine
   register names.
*/

#if defined( ARRAYS )
#define s(x,c) x[c]
#else
#define s(x,c) x##c
#endif

/*  This implementation provides subroutines for encryption, decryption
    and for setting the three key lengths (separately) for encryption
    and decryption. Since not all functions are needed, masks are set
    up here to determine which will be implemented in C
*/

#if !defined( AES_ENCRYPT )
#  define EFUNCS_IN_C   0
#elif defined( ASSUME_VIA_ACE_PRESENT ) || defined( ASM_X86_V1C ) \
    || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C )
#  define EFUNCS_IN_C   ENC_KEYING_IN_C
#elif !defined( ASM_X86_V2 )
#  define EFUNCS_IN_C   ( ENCRYPTION_IN_C | ENC_KEYING_IN_C )
#else
#  define EFUNCS_IN_C   0
#endif

#if !defined( AES_DECRYPT )
#  define DFUNCS_IN_C   0
#elif defined( ASSUME_VIA_ACE_PRESENT ) || defined( ASM_X86_V1C ) \
    || defined( ASM_X86_V2C ) || defined( ASM_AMD64_C )
#  define DFUNCS_IN_C   DEC_KEYING_IN_C
#elif !defined( ASM_X86_V2 )
#  define DFUNCS_IN_C   ( DECRYPTION_IN_C | DEC_KEYING_IN_C )
#else
#  define DFUNCS_IN_C   0
#endif

#define FUNCS_IN_C  ( EFUNCS_IN_C | DFUNCS_IN_C )

/* END OF CONFIGURATION OPTIONS */

#define RC_LENGTH   (5 * (AES_BLOCK_SIZE / 4 - 2))

/* Disable or report errors on some combinations of options */

#if ENC_ROUND == NO_TABLES && LAST_ENC_ROUND != NO_TABLES
#undef  LAST_ENC_ROUND
#define LAST_ENC_ROUND  NO_TABLES
#elif ENC_ROUND == ONE_TABLE && LAST_ENC_ROUND == FOUR_TABLES
#undef  LAST_ENC_ROUND
#define LAST_ENC_ROUND  ONE_TABLE
#endif

#if ENC_ROUND == NO_TABLES && ENC_UNROLL != NONE
#undef  ENC_UNROLL
#define ENC_UNROLL  NONE
#endif

#if DEC_ROUND == NO_TABLES && LAST_DEC_ROUND != NO_TABLES
#undef  LAST_DEC_ROUND
#define LAST_DEC_ROUND  NO_TABLES
#elif DEC_ROUND == ONE_TABLE && LAST_DEC_ROUND == FOUR_TABLES
#undef  LAST_DEC_ROUND
#define LAST_DEC_ROUND  ONE_TABLE
#endif

#if DEC_ROUND == NO_TABLES && DEC_UNROLL != NONE
#undef  DEC_UNROLL
#define DEC_UNROLL  NONE
#endif

#if defined( bswap32 )
#define aes_sw32    bswap32
#elif defined( bswap_32 )
#define aes_sw32    bswap_32
#else
#define brot(x,n)   (((uint_32t)(x) <<  n) | ((uint_32t)(x) >> (32 - n)))
#define aes_sw32(x) ((brot((x),8) & 0x00ff00ff) | (brot((x),24) & 0xff00ff00))
#endif

/*  upr(x,n):  rotates bytes within words by n positions, moving bytes to
               higher index positions with wrap around into low positions
    ups(x,n):  moves bytes by n positions to higher index positions in
               words but without wrap around
    bval(x,n): extracts a byte from a word

    WARNING:   The definitions given here are intended only for use with
               unsigned variables and with shift counts that are compile
               time constants
*/

#if ( ALGORITHM_BYTE_ORDER == IS_LITTLE_ENDIAN )
#define upr(x,n)        (((uint_32t)(x) << (8 * (n))) | ((uint_32t)(x) >> (32 - 8 * (n))))
#define ups(x,n)        ((uint_32t) (x) << (8 * (n)))
#define bval(x,n)       ((uint_8t)((x) >> (8 * (n))))
#define bytes2word(b0, b1, b2, b3)  \
        (((uint_32t)(b3) << 24) | ((uint_32t)(b2) << 16) | ((uint_32t)(b1) << 8) | (b0))
#endif

#if ( ALGORITHM_BYTE_ORDER == IS_BIG_ENDIAN )
#define upr(x,n)        (((uint_32t)(x) >> (8 * (n))) | ((uint_32t)(x) << (32 - 8 * (n))))
#define ups(x,n)        ((uint_32t) (x) >> (8 * (n)))
#define bval(x,n)       ((uint_8t)((x) >> (24 - 8 * (n))))
#define bytes2word(b0, b1, b2, b3)  \
        (((uint_32t)(b0) << 24) | ((uint_32t)(b1) << 16) | ((uint_32t)(b2) << 8) | (b3))
#endif

#if defined( SAFE_IO )

#define word_in(x,c)    bytes2word(((const uint_8t*)(x)+4*c)[0], ((const uint_8t*)(x)+4*c)[1], \
                                   ((const uint_8t*)(x)+4*c)[2], ((const uint_8t*)(x)+4*c)[3])
#define word_out(x,c,v) { ((uint_8t*)(x)+4*c)[0] = bval(v,0); ((uint_8t*)(x)+4*c)[1] = bval(v,1); \
                          ((uint_8t*)(x)+4*c)[2] = bval(v,2); ((uint_8t*)(x)+4*c)[3] = bval(v,3); }

#elif ( ALGORITHM_BYTE_ORDER == PLATFORM_BYTE_ORDER )

#define word_in(x,c)    (*((uint_32t*)(x)+(c)))
#define word_out(x,c,v) (*((uint_32t*)(x)+(c)) = (v))

#else
#define word_in(x,c)    aes_sw32(*((uint_32t*)(x)+(c)))
#define word_out(x,c,v) (*((uint_32t*)(x)+(c)) = aes_sw32(v))

#endif

/* the finite field modular polynomial and elements */

#define WPOLY   0x011b
#define BPOLY     0x1b

/* multiply four bytes in GF(2^8) by 'x' {02} in parallel */

#define m1  0x80808080
#define m2  0x7f7f7f7f
#define gf_mulx(x)  ((((x) & m2) << 1) ^ ((((x) & m1) >> 7) * BPOLY))

/* The following defines provide alternative definitions of gf_mulx that might
   give improved performance if a fast 32-bit multiply is not available. Note
   that a temporary variable u needs to be defined where gf_mulx is used.

#define gf_mulx(x) (u = (x) & m1, u |= (u >> 1), ((x) & m2) << 1) ^ ((u >> 3) | (u >> 6))
#define m4  (0x01010101 * BPOLY)
#define gf_mulx(x) (u = (x) & m1, ((x) & m2) << 1) ^ ((u - (u >> 7)) & m4)
*/

/* Work out which tables are needed for the different options   */

#if defined( ASM_X86_V1C )
#if defined( ENC_ROUND )
#undef  ENC_ROUND
#endif
#define ENC_ROUND   FOUR_TABLES
#if defined( LAST_ENC_ROUND )
#undef  LAST_ENC_ROUND
#endif
#define LAST_ENC_ROUND  FOUR_TABLES
#if defined( DEC_ROUND )
#undef  DEC_ROUND
#endif
#define DEC_ROUND   FOUR_TABLES
#if defined( LAST_DEC_ROUND )
#undef  LAST_DEC_ROUND
#endif
#define LAST_DEC_ROUND  FOUR_TABLES
#if defined( KEY_SCHED )
#undef  KEY_SCHED
#define KEY_SCHED   FOUR_TABLES
#endif
#endif

#if ( FUNCS_IN_C & ENCRYPTION_IN_C ) || defined( ASM_X86_V1C )
#if ENC_ROUND == ONE_TABLE
#define FT1_SET
#elif ENC_ROUND == FOUR_TABLES
#define FT4_SET
#else
#define SBX_SET
#endif
#if LAST_ENC_ROUND == ONE_TABLE
#define FL1_SET
#elif LAST_ENC_ROUND == FOUR_TABLES
#define FL4_SET
#elif !defined( SBX_SET )
#define SBX_SET
#endif
#endif

#if ( FUNCS_IN_C & DECRYPTION_IN_C ) || defined( ASM_X86_V1C )
#if DEC_ROUND == ONE_TABLE
#define IT1_SET
#elif DEC_ROUND == FOUR_TABLES
#define IT4_SET
#else
#define ISB_SET
#endif
#if LAST_DEC_ROUND == ONE_TABLE
#define IL1_SET
#elif LAST_DEC_ROUND == FOUR_TABLES
#define IL4_SET
#elif !defined(ISB_SET)
#define ISB_SET
#endif
#endif

#if (FUNCS_IN_C & ENC_KEYING_IN_C) || (FUNCS_IN_C & DEC_KEYING_IN_C)
#if KEY_SCHED == ONE_TABLE
#define LS1_SET
#elif KEY_SCHED == FOUR_TABLES
#define LS4_SET
#elif !defined( SBX_SET )
#define SBX_SET
#endif
#endif

#if (FUNCS_IN_C & DEC_KEYING_IN_C)
#if KEY_SCHED == ONE_TABLE
#define IM1_SET
#elif KEY_SCHED == FOUR_TABLES
#define IM4_SET
#elif !defined( SBX_SET )
#define SBX_SET
#endif
#endif

/* generic definitions of Rijndael macros that use tables    */

#define no_table(x,box,vf,rf,c) bytes2word( \
    box[bval(vf(x,0,c),rf(0,c))], \
    box[bval(vf(x,1,c),rf(1,c))], \
    box[bval(vf(x,2,c),rf(2,c))], \
    box[bval(vf(x,3,c),rf(3,c))])

#define one_table(x,op,tab,vf,rf,c) \
 (     tab[bval(vf(x,0,c),rf(0,c))] \
  ^ op(tab[bval(vf(x,1,c),rf(1,c))],1) \
  ^ op(tab[bval(vf(x,2,c),rf(2,c))],2) \
  ^ op(tab[bval(vf(x,3,c),rf(3,c))],3))

#define four_tables(x,tab,vf,rf,c) \
 (  tab[0][bval(vf(x,0,c),rf(0,c))] \
  ^ tab[1][bval(vf(x,1,c),rf(1,c))] \
  ^ tab[2][bval(vf(x,2,c),rf(2,c))] \
  ^ tab[3][bval(vf(x,3,c),rf(3,c))])

#define vf1(x,r,c)  (x)
#define rf1(r,c)    (r)
#define rf2(r,c)    ((8+r-c)&3)

/* perform forward and inverse column mix operation on four bytes in long word x in */
/* parallel. NOTE: x must be a simple variable, NOT an expression in these macros.  */

#if defined( FM4_SET )    /* not currently used */
#define fwd_mcol(x)       four_tables(x,t_use(f,m),vf1,rf1,0)
#elif defined( FM1_SET )  /* not currently used */
#define fwd_mcol(x)       one_table(x,upr,t_use(f,m),vf1,rf1,0)
#else
#define dec_fmvars        uint_32t g2
#define fwd_mcol(x)       (g2 = gf_mulx(x), g2 ^ upr((x) ^ g2, 3) ^ upr((x), 2) ^ upr((x), 1))
#endif

#if defined( IM4_SET )
#define inv_mcol(x)       four_tables(x,t_use(i,m),vf1,rf1,0)
#elif defined( IM1_SET )
#define inv_mcol(x)       one_table(x,upr,t_use(i,m),vf1,rf1,0)
#else
#define dec_imvars        uint_32t g2, g4, g9
#define inv_mcol(x)       (g2 = gf_mulx(x), g4 = gf_mulx(g2), g9 = (x) ^ gf_mulx(g4), g4 ^= g9, \
                          (x) ^ g2 ^ g4 ^ upr(g2 ^ g9, 3) ^ upr(g4, 2) ^ upr(g9, 1))
#endif

#if defined( FL4_SET )
#define ls_box(x,c)       four_tables(x,t_use(f,l),vf1,rf2,c)
#elif   defined( LS4_SET )
#define ls_box(x,c)       four_tables(x,t_use(l,s),vf1,rf2,c)
#elif defined( FL1_SET )
#define ls_box(x,c)       one_table(x,upr,t_use(f,l),vf1,rf2,c)
#elif defined( LS1_SET )
#define ls_box(x,c)       one_table(x,upr,t_use(l,s),vf1,rf2,c)
#else
#define ls_box(x,c)     no_table(x,t_use(s,box),vf1,rf2,c)
#endif

#if defined( ASM_X86_V1C ) && defined( AES_DECRYPT ) && !defined( ISB_SET )
#define ISB_SET
#endif

#endif

/*
 * Aestab.h
 */

/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007

 This file contains the code for declaring the tables needed to implement
 AES. The file aesopt.h is assumed to be included before this header file.
 If there are no global variables, the definitions here can be used to put
 the AES tables in a structure so that a pointer can then be added to the
 AES context to pass them to the AES routines that need them.   If this
 facility is used, the calling program has to ensure that this pointer is
 managed appropriately.  In particular, the value of the t_dec(in,it) item
 in the table structure must be set to zero in order to ensure that the
 tables are initialised. In practice the three code sequences in aeskey.c
 that control the calls to aes_init() and the aes_init() routine itself will
 have to be changed for a specific implementation. If global variables are
 available it will generally be preferable to use them with the precomputed
 FIXED_TABLES option that uses static global tables.

 The following defines can be used to control the way the tables
 are defined, initialised and used in embedded environments that
 require special features for these purposes

    the 't_dec' construction is used to declare fixed table arrays
    the 't_set' construction is used to set fixed table values
    the 't_use' construction is used to access fixed table values

    256 byte tables:

        t_xxx(s,box)    => forward S box
        t_xxx(i,box)    => inverse S box

    256 32-bit word OR 4 x 256 32-bit word tables:

        t_xxx(f,n)      => forward normal round
        t_xxx(f,l)      => forward last round
        t_xxx(i,n)      => inverse normal round
        t_xxx(i,l)      => inverse last round
        t_xxx(l,s)      => key schedule table
        t_xxx(i,m)      => key schedule table

    Other variables and tables:

        t_xxx(r,c)      => the rcon table
*/

#if !defined( _AESTAB_H )
#define _AESTAB_H

#define t_dec(m,n) t_##m##n
#define t_set(m,n) t_##m##n
#define t_use(m,n) t_##m##n

#if defined(FIXED_TABLES)
#  if !defined( __GNUC__ ) && (defined( __MSDOS__ ) || defined( __WIN16__ ))
/*   make tables far data to avoid using too much DGROUP space (PG) */
#    define CONST const far
#  else
#    define CONST const
#  endif
#else
#  define CONST
#endif

#if defined(__cplusplus)
#  define EXTERN extern "C"
#elif defined(DO_TABLES)
#  define EXTERN
#else
#  define EXTERN extern
#endif

#if defined(_MSC_VER) && defined(TABLE_ALIGN)
#define ALIGN __declspec(align(TABLE_ALIGN))
#else
#define ALIGN
#endif

#if defined( __WATCOMC__ ) && ( __WATCOMC__ >= 1100 )
#  define XP_DIR __cdecl
#else
#  define XP_DIR
#endif

#if defined( _GPU_ )
#  define DEVICE __device__
#else
#  define DEVICE
#endif

/* Changed */
#if defined(DO_TABLES) && defined(FIXED_TABLES)
#define d_1(t,n,b,e)       EXTERN ALIGN  XP_DIR t n[256]    =   b(e)
#define d_4(t,n,b,e,f,g,h) EXTERN ALIGN  XP_DIR t n[4][256] = { b(e), b(f), b(g), b(h) }
EXTERN ALIGN  uint_32t t_dec(r,c)[RC_LENGTH] = rc_data(w0);
#else
#define d_1(t,n,b,e)       EXTERN ALIGN  XP_DIR t n[256]
#define d_4(t,n,b,e,f,g,h) EXTERN ALIGN  XP_DIR t n[4][256]
EXTERN ALIGN  uint_32t t_dec(r,c)[RC_LENGTH];
#endif

#if defined( SBX_SET )
d_1(uint_8t, t_dec(s,box), sb_data, h0);
#endif
#if defined( ISB_SET )
d_1(uint_8t, t_dec(i,box), isb_data, h0);
#endif

#if defined( FT1_SET )
d_1(uint_32t, t_dec(f,n), sb_data, u0);
#endif
#if defined( FT4_SET )
d_4(uint_32t, t_dec(f,n), sb_data, u0, u1, u2, u3);
#endif

#if defined( FL1_SET )
d_1(uint_32t, t_dec(f,l), sb_data, w0);
#endif
#if defined( FL4_SET )
d_4(uint_32t, t_dec(f,l), sb_data, w0, w1, w2, w3);
#endif

#if defined( IT1_SET )
d_1(uint_32t, t_dec(i,n), isb_data, v0);
#endif
#if defined( IT4_SET )
d_4(uint_32t, t_dec(i,n), isb_data, v0, v1, v2, v3);
#endif

#if defined( IL1_SET )
d_1(uint_32t, t_dec(i,l), isb_data, w0);
#endif
#if defined( IL4_SET )
d_4(uint_32t, t_dec(i,l), isb_data, w0, w1, w2, w3);
#endif

#if defined( LS1_SET )
#if defined( FL1_SET )
#undef  LS1_SET
#else
d_1(uint_32t, t_dec(l,s), sb_data, w0);
#endif
#endif

#if defined( LS4_SET )
#if defined( FL4_SET )
#undef  LS4_SET
#else
d_4(uint_32t, t_dec(l,s), sb_data, w0, w1, w2, w3);
#endif
#endif

#if defined( IM1_SET )
d_1(uint_32t, t_dec(i,m), mm_data, v0);
#endif
#if defined( IM4_SET )
d_4(uint_32t, t_dec(i,m), mm_data, v0, v1, v2, v3);
#endif

#endif

/*
 * Aestab.c
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007
*/

/* Adapted for TrueCrypt:
   - Added run-time table generator for Aes_x86_v2.asm
*/

#define DO_TABLES

#if defined(FIXED_TABLES)

#define sb_data(w) {\
    w(0x63), w(0x7c), w(0x77), w(0x7b), w(0xf2), w(0x6b), w(0x6f), w(0xc5),\
    w(0x30), w(0x01), w(0x67), w(0x2b), w(0xfe), w(0xd7), w(0xab), w(0x76),\
    w(0xca), w(0x82), w(0xc9), w(0x7d), w(0xfa), w(0x59), w(0x47), w(0xf0),\
    w(0xad), w(0xd4), w(0xa2), w(0xaf), w(0x9c), w(0xa4), w(0x72), w(0xc0),\
    w(0xb7), w(0xfd), w(0x93), w(0x26), w(0x36), w(0x3f), w(0xf7), w(0xcc),\
    w(0x34), w(0xa5), w(0xe5), w(0xf1), w(0x71), w(0xd8), w(0x31), w(0x15),\
    w(0x04), w(0xc7), w(0x23), w(0xc3), w(0x18), w(0x96), w(0x05), w(0x9a),\
    w(0x07), w(0x12), w(0x80), w(0xe2), w(0xeb), w(0x27), w(0xb2), w(0x75),\
    w(0x09), w(0x83), w(0x2c), w(0x1a), w(0x1b), w(0x6e), w(0x5a), w(0xa0),\
    w(0x52), w(0x3b), w(0xd6), w(0xb3), w(0x29), w(0xe3), w(0x2f), w(0x84),\
    w(0x53), w(0xd1), w(0x00), w(0xed), w(0x20), w(0xfc), w(0xb1), w(0x5b),\
    w(0x6a), w(0xcb), w(0xbe), w(0x39), w(0x4a), w(0x4c), w(0x58), w(0xcf),\
    w(0xd0), w(0xef), w(0xaa), w(0xfb), w(0x43), w(0x4d), w(0x33), w(0x85),\
    w(0x45), w(0xf9), w(0x02), w(0x7f), w(0x50), w(0x3c), w(0x9f), w(0xa8),\
    w(0x51), w(0xa3), w(0x40), w(0x8f), w(0x92), w(0x9d), w(0x38), w(0xf5),\
    w(0xbc), w(0xb6), w(0xda), w(0x21), w(0x10), w(0xff), w(0xf3), w(0xd2),\
    w(0xcd), w(0x0c), w(0x13), w(0xec), w(0x5f), w(0x97), w(0x44), w(0x17),\
    w(0xc4), w(0xa7), w(0x7e), w(0x3d), w(0x64), w(0x5d), w(0x19), w(0x73),\
    w(0x60), w(0x81), w(0x4f), w(0xdc), w(0x22), w(0x2a), w(0x90), w(0x88),\
    w(0x46), w(0xee), w(0xb8), w(0x14), w(0xde), w(0x5e), w(0x0b), w(0xdb),\
    w(0xe0), w(0x32), w(0x3a), w(0x0a), w(0x49), w(0x06), w(0x24), w(0x5c),\
    w(0xc2), w(0xd3), w(0xac), w(0x62), w(0x91), w(0x95), w(0xe4), w(0x79),\
    w(0xe7), w(0xc8), w(0x37), w(0x6d), w(0x8d), w(0xd5), w(0x4e), w(0xa9),\
    w(0x6c), w(0x56), w(0xf4), w(0xea), w(0x65), w(0x7a), w(0xae), w(0x08),\
    w(0xba), w(0x78), w(0x25), w(0x2e), w(0x1c), w(0xa6), w(0xb4), w(0xc6),\
    w(0xe8), w(0xdd), w(0x74), w(0x1f), w(0x4b), w(0xbd), w(0x8b), w(0x8a),\
    w(0x70), w(0x3e), w(0xb5), w(0x66), w(0x48), w(0x03), w(0xf6), w(0x0e),\
    w(0x61), w(0x35), w(0x57), w(0xb9), w(0x86), w(0xc1), w(0x1d), w(0x9e),\
    w(0xe1), w(0xf8), w(0x98), w(0x11), w(0x69), w(0xd9), w(0x8e), w(0x94),\
    w(0x9b), w(0x1e), w(0x87), w(0xe9), w(0xce), w(0x55), w(0x28), w(0xdf),\
    w(0x8c), w(0xa1), w(0x89), w(0x0d), w(0xbf), w(0xe6), w(0x42), w(0x68),\
    w(0x41), w(0x99), w(0x2d), w(0x0f), w(0xb0), w(0x54), w(0xbb), w(0x16) }

#define isb_data(w) {\
    w(0x52), w(0x09), w(0x6a), w(0xd5), w(0x30), w(0x36), w(0xa5), w(0x38),\
    w(0xbf), w(0x40), w(0xa3), w(0x9e), w(0x81), w(0xf3), w(0xd7), w(0xfb),\
    w(0x7c), w(0xe3), w(0x39), w(0x82), w(0x9b), w(0x2f), w(0xff), w(0x87),\
    w(0x34), w(0x8e), w(0x43), w(0x44), w(0xc4), w(0xde), w(0xe9), w(0xcb),\
    w(0x54), w(0x7b), w(0x94), w(0x32), w(0xa6), w(0xc2), w(0x23), w(0x3d),\
    w(0xee), w(0x4c), w(0x95), w(0x0b), w(0x42), w(0xfa), w(0xc3), w(0x4e),\
    w(0x08), w(0x2e), w(0xa1), w(0x66), w(0x28), w(0xd9), w(0x24), w(0xb2),\
    w(0x76), w(0x5b), w(0xa2), w(0x49), w(0x6d), w(0x8b), w(0xd1), w(0x25),\
    w(0x72), w(0xf8), w(0xf6), w(0x64), w(0x86), w(0x68), w(0x98), w(0x16),\
    w(0xd4), w(0xa4), w(0x5c), w(0xcc), w(0x5d), w(0x65), w(0xb6), w(0x92),\
    w(0x6c), w(0x70), w(0x48), w(0x50), w(0xfd), w(0xed), w(0xb9), w(0xda),\
    w(0x5e), w(0x15), w(0x46), w(0x57), w(0xa7), w(0x8d), w(0x9d), w(0x84),\
    w(0x90), w(0xd8), w(0xab), w(0x00), w(0x8c), w(0xbc), w(0xd3), w(0x0a),\
    w(0xf7), w(0xe4), w(0x58), w(0x05), w(0xb8), w(0xb3), w(0x45), w(0x06),\
    w(0xd0), w(0x2c), w(0x1e), w(0x8f), w(0xca), w(0x3f), w(0x0f), w(0x02),\
    w(0xc1), w(0xaf), w(0xbd), w(0x03), w(0x01), w(0x13), w(0x8a), w(0x6b),\
    w(0x3a), w(0x91), w(0x11), w(0x41), w(0x4f), w(0x67), w(0xdc), w(0xea),\
    w(0x97), w(0xf2), w(0xcf), w(0xce), w(0xf0), w(0xb4), w(0xe6), w(0x73),\
    w(0x96), w(0xac), w(0x74), w(0x22), w(0xe7), w(0xad), w(0x35), w(0x85),\
    w(0xe2), w(0xf9), w(0x37), w(0xe8), w(0x1c), w(0x75), w(0xdf), w(0x6e),\
    w(0x47), w(0xf1), w(0x1a), w(0x71), w(0x1d), w(0x29), w(0xc5), w(0x89),\
    w(0x6f), w(0xb7), w(0x62), w(0x0e), w(0xaa), w(0x18), w(0xbe), w(0x1b),\
    w(0xfc), w(0x56), w(0x3e), w(0x4b), w(0xc6), w(0xd2), w(0x79), w(0x20),\
    w(0x9a), w(0xdb), w(0xc0), w(0xfe), w(0x78), w(0xcd), w(0x5a), w(0xf4),\
    w(0x1f), w(0xdd), w(0xa8), w(0x33), w(0x88), w(0x07), w(0xc7), w(0x31),\
    w(0xb1), w(0x12), w(0x10), w(0x59), w(0x27), w(0x80), w(0xec), w(0x5f),\
    w(0x60), w(0x51), w(0x7f), w(0xa9), w(0x19), w(0xb5), w(0x4a), w(0x0d),\
    w(0x2d), w(0xe5), w(0x7a), w(0x9f), w(0x93), w(0xc9), w(0x9c), w(0xef),\
    w(0xa0), w(0xe0), w(0x3b), w(0x4d), w(0xae), w(0x2a), w(0xf5), w(0xb0),\
    w(0xc8), w(0xeb), w(0xbb), w(0x3c), w(0x83), w(0x53), w(0x99), w(0x61),\
    w(0x17), w(0x2b), w(0x04), w(0x7e), w(0xba), w(0x77), w(0xd6), w(0x26),\
    w(0xe1), w(0x69), w(0x14), w(0x63), w(0x55), w(0x21), w(0x0c), w(0x7d) }

#define mm_data(w) {\
    w(0x00), w(0x01), w(0x02), w(0x03), w(0x04), w(0x05), w(0x06), w(0x07),\
    w(0x08), w(0x09), w(0x0a), w(0x0b), w(0x0c), w(0x0d), w(0x0e), w(0x0f),\
    w(0x10), w(0x11), w(0x12), w(0x13), w(0x14), w(0x15), w(0x16), w(0x17),\
    w(0x18), w(0x19), w(0x1a), w(0x1b), w(0x1c), w(0x1d), w(0x1e), w(0x1f),\
    w(0x20), w(0x21), w(0x22), w(0x23), w(0x24), w(0x25), w(0x26), w(0x27),\
    w(0x28), w(0x29), w(0x2a), w(0x2b), w(0x2c), w(0x2d), w(0x2e), w(0x2f),\
    w(0x30), w(0x31), w(0x32), w(0x33), w(0x34), w(0x35), w(0x36), w(0x37),\
    w(0x38), w(0x39), w(0x3a), w(0x3b), w(0x3c), w(0x3d), w(0x3e), w(0x3f),\
    w(0x40), w(0x41), w(0x42), w(0x43), w(0x44), w(0x45), w(0x46), w(0x47),\
    w(0x48), w(0x49), w(0x4a), w(0x4b), w(0x4c), w(0x4d), w(0x4e), w(0x4f),\
    w(0x50), w(0x51), w(0x52), w(0x53), w(0x54), w(0x55), w(0x56), w(0x57),\
    w(0x58), w(0x59), w(0x5a), w(0x5b), w(0x5c), w(0x5d), w(0x5e), w(0x5f),\
    w(0x60), w(0x61), w(0x62), w(0x63), w(0x64), w(0x65), w(0x66), w(0x67),\
    w(0x68), w(0x69), w(0x6a), w(0x6b), w(0x6c), w(0x6d), w(0x6e), w(0x6f),\
    w(0x70), w(0x71), w(0x72), w(0x73), w(0x74), w(0x75), w(0x76), w(0x77),\
    w(0x78), w(0x79), w(0x7a), w(0x7b), w(0x7c), w(0x7d), w(0x7e), w(0x7f),\
    w(0x80), w(0x81), w(0x82), w(0x83), w(0x84), w(0x85), w(0x86), w(0x87),\
    w(0x88), w(0x89), w(0x8a), w(0x8b), w(0x8c), w(0x8d), w(0x8e), w(0x8f),\
    w(0x90), w(0x91), w(0x92), w(0x93), w(0x94), w(0x95), w(0x96), w(0x97),\
    w(0x98), w(0x99), w(0x9a), w(0x9b), w(0x9c), w(0x9d), w(0x9e), w(0x9f),\
    w(0xa0), w(0xa1), w(0xa2), w(0xa3), w(0xa4), w(0xa5), w(0xa6), w(0xa7),\
    w(0xa8), w(0xa9), w(0xaa), w(0xab), w(0xac), w(0xad), w(0xae), w(0xaf),\
    w(0xb0), w(0xb1), w(0xb2), w(0xb3), w(0xb4), w(0xb5), w(0xb6), w(0xb7),\
    w(0xb8), w(0xb9), w(0xba), w(0xbb), w(0xbc), w(0xbd), w(0xbe), w(0xbf),\
    w(0xc0), w(0xc1), w(0xc2), w(0xc3), w(0xc4), w(0xc5), w(0xc6), w(0xc7),\
    w(0xc8), w(0xc9), w(0xca), w(0xcb), w(0xcc), w(0xcd), w(0xce), w(0xcf),\
    w(0xd0), w(0xd1), w(0xd2), w(0xd3), w(0xd4), w(0xd5), w(0xd6), w(0xd7),\
    w(0xd8), w(0xd9), w(0xda), w(0xdb), w(0xdc), w(0xdd), w(0xde), w(0xdf),\
    w(0xe0), w(0xe1), w(0xe2), w(0xe3), w(0xe4), w(0xe5), w(0xe6), w(0xe7),\
    w(0xe8), w(0xe9), w(0xea), w(0xeb), w(0xec), w(0xed), w(0xee), w(0xef),\
    w(0xf0), w(0xf1), w(0xf2), w(0xf3), w(0xf4), w(0xf5), w(0xf6), w(0xf7),\
    w(0xf8), w(0xf9), w(0xfa), w(0xfb), w(0xfc), w(0xfd), w(0xfe), w(0xff) }

#define rc_data(w) {\
    w(0x01), w(0x02), w(0x04), w(0x08), w(0x10),w(0x20), w(0x40), w(0x80),\
    w(0x1b), w(0x36) }

#define h0(x)   (x)

#define w0(p)   bytes2word(p, 0, 0, 0)
#define w1(p)   bytes2word(0, p, 0, 0)
#define w2(p)   bytes2word(0, 0, p, 0)
#define w3(p)   bytes2word(0, 0, 0, p)

#define u0(p)   bytes2word(f2(p), p, p, f3(p))
#define u1(p)   bytes2word(f3(p), f2(p), p, p)
#define u2(p)   bytes2word(p, f3(p), f2(p), p)
#define u3(p)   bytes2word(p, p, f3(p), f2(p))

#define v0(p)   bytes2word(fe(p), f9(p), fd(p), fb(p))
#define v1(p)   bytes2word(fb(p), fe(p), f9(p), fd(p))
#define v2(p)   bytes2word(fd(p), fb(p), fe(p), f9(p))
#define v3(p)   bytes2word(f9(p), fd(p), fb(p), fe(p))

#endif

#if defined(FIXED_TABLES) || !defined(FF_TABLES)

#define f2(x)   ((x<<1) ^ (((x>>7) & 1) * WPOLY))
#define f4(x)   ((x<<2) ^ (((x>>6) & 1) * WPOLY) ^ (((x>>6) & 2) * WPOLY))
#define f8(x)   ((x<<3) ^ (((x>>5) & 1) * WPOLY) ^ (((x>>5) & 2) * WPOLY) \
                        ^ (((x>>5) & 4) * WPOLY))
#define f3(x)   (f2(x) ^ x)
#define f9(x)   (f8(x) ^ x)
#define fb(x)   (f8(x) ^ f2(x) ^ x)
#define fd(x)   (f8(x) ^ f4(x) ^ x)
#define fe(x)   (f8(x) ^ f4(x) ^ f2(x))

#else

#define f2(x) ((x) ? pow[log[x] + 0x19] : 0)
#define f3(x) ((x) ? pow[log[x] + 0x01] : 0)
#define f9(x) ((x) ? pow[log[x] + 0xc7] : 0)
#define fb(x) ((x) ? pow[log[x] + 0x68] : 0)
#define fd(x) ((x) ? pow[log[x] + 0xee] : 0)
#define fe(x) ((x) ? pow[log[x] + 0xdf] : 0)
#define fi(x) ((x) ? pow[ 255 - log[x]] : 0)

#endif


#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(FIXED_TABLES)

    /* implemented in case of wrong call for fixed tables */

    AES_RETURN aes_init(void)
    {
        return EXIT_SUCCESS;
    }

#else   /* dynamic table generation */

#if !defined(FF_TABLES)

    /*  Generate the tables for the dynamic table option

        It will generally be sensible to use tables to compute finite
        field multiplies and inverses but where memory is scarse this
        code might sometimes be better. But it only has effect during
        initialisation so its pretty unimportant in overall terms.
    */

    /*  return 2 ^ (n - 1) where n is the bit number of the highest bit
        set in x with x in the range 1 < x < 0x00000200.   This form is
        used so that locals within fi can be bytes rather than words
    */

    static uint_8t hibit(const uint_32t x)
    {
        uint_8t r = (uint_8t)((x >> 1) | (x >> 2));

        r |= (r >> 2);
        r |= (r >> 4);
        return (r + 1) >> 1;
    }

    /* return the inverse of the finite field element x */

    static uint_8t fi(const uint_8t x)
    {
        uint_8t p1 = x, p2 = BPOLY, n1 = hibit(x), n2 = 0x80, v1 = 1, v2 = 0;

        if (x < 2) return x;

        for (;;)
        {
            if (!n1) return v1;

            while (n2 >= n1)
            {
                n2 /= n1;
                p2 ^= p1 * n2;
                v2 ^= v1 * n2;
                n2 = hibit(p2);
            }

            if (!n2) return v2;

            while (n1 >= n2)
            {
                n1 /= n2;
                p1 ^= p2 * n1;
                v1 ^= v2 * n1;
                n1 = hibit(p1);
            }
        }
    }

#endif

    /* The forward and inverse affine transformations used in the S-box */

#define fwd_affine(x) \
    (w = (uint_32t)x, w ^= (w<<1)^(w<<2)^(w<<3)^(w<<4), 0x63^(uint_8t)(w^(w>>8)))

#define inv_affine(x) \
    (w = (uint_32t)x, w = (w<<1)^(w<<3)^(w<<6), 0x05^(uint_8t)(w^(w>>8)))

    static int init = 0;

#ifdef TC_WINDOWS_BOOT

#pragma optimize ("l", on)
    uint_8t aes_enc_tab[256][8];
    uint_8t aes_dec_tab[256][8];

#endif

    AES_RETURN aes_init(void)
    {
        uint_32t  i, w;


#if defined(FF_TABLES)

        uint_8t  pow[512], log[256];

        if (init)
            return EXIT_SUCCESS;
        /*  log and power tables for GF(2^8) finite field with
            WPOLY as modular polynomial - the simplest primitive
            root is 0x03, used here to generate the tables
        */

        i = 0;
        w = 1;
        do
        {
            pow[i] = (uint_8t)w;
            pow[i + 255] = (uint_8t)w;
            log[w] = (uint_8t)i++;
            w ^=  (w << 1) ^ (w & 0x80 ? WPOLY : 0);
        }
        while (w != 1);

#else
        if (init)
            return EXIT_SUCCESS;
#endif

        for (i = 0, w = 1; i < RC_LENGTH; ++i)
        {
            t_set(r,c)[i] = bytes2word(w, 0, 0, 0);
            w = f2(w);
        }

        for (i = 0; i < 256; ++i)
        {
            uint_8t    b;

            b = fwd_affine(fi((uint_8t)i));
            w = bytes2word(f2(b), b, b, f3(b));

#if defined( SBX_SET )
            t_set(s,box)[i] = b;
#endif

#if defined( FT1_SET )                 /* tables for a normal encryption round */
            t_set(f,n)[i] = w;
#endif
#if defined( FT4_SET )
            t_set(f,n)[0][i] = w;
            t_set(f,n)[1][i] = upr(w,1);
            t_set(f,n)[2][i] = upr(w,2);
            t_set(f,n)[3][i] = upr(w,3);
#endif
            w = bytes2word(b, 0, 0, 0);

#if defined( FL1_SET )            /* tables for last encryption round (may also   */
            t_set(f,l)[i] = w;        /* be used in the key schedule)                 */
#endif
#if defined( FL4_SET )
            t_set(f,l)[0][i] = w;
            t_set(f,l)[1][i] = upr(w,1);
            t_set(f,l)[2][i] = upr(w,2);
            t_set(f,l)[3][i] = upr(w,3);
#endif

#if defined( LS1_SET )			/* table for key schedule if t_set(f,l) above is*/
            t_set(l,s)[i] = w;      /* not of the required form                     */
#endif
#if defined( LS4_SET )
            t_set(l,s)[0][i] = w;
            t_set(l,s)[1][i] = upr(w,1);
            t_set(l,s)[2][i] = upr(w,2);
            t_set(l,s)[3][i] = upr(w,3);
#endif

            b = fi(inv_affine((uint_8t)i));
            w = bytes2word(fe(b), f9(b), fd(b), fb(b));

#if defined( IM1_SET )			/* tables for the inverse mix column operation  */
            t_set(i,m)[b] = w;
#endif
#if defined( IM4_SET )
            t_set(i,m)[0][b] = w;
            t_set(i,m)[1][b] = upr(w,1);
            t_set(i,m)[2][b] = upr(w,2);
            t_set(i,m)[3][b] = upr(w,3);
#endif

#if defined( ISB_SET )
            t_set(i,box)[i] = b;
#endif
#if defined( IT1_SET )			/* tables for a normal decryption round */
            t_set(i,n)[i] = w;
#endif
#if defined( IT4_SET )
            t_set(i,n)[0][i] = w;
            t_set(i,n)[1][i] = upr(w,1);
            t_set(i,n)[2][i] = upr(w,2);
            t_set(i,n)[3][i] = upr(w,3);
#endif
            w = bytes2word(b, 0, 0, 0);
#if defined( IL1_SET )			/* tables for last decryption round */
            t_set(i,l)[i] = w;
#endif
#if defined( IL4_SET )
            t_set(i,l)[0][i] = w;
            t_set(i,l)[1][i] = upr(w,1);
            t_set(i,l)[2][i] = upr(w,2);
            t_set(i,l)[3][i] = upr(w,3);
#endif
        }


        init = 1;
        return EXIT_SUCCESS;
    }

#endif

#if defined(__cplusplus)
}
#endif


/*
 * Aeskey.c
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007
*/


#if defined(__cplusplus)
extern "C"
{
#endif

    /* Initialise the key schedule from the user supplied key. The key
       length can be specified in bytes, with legal values of 16, 24
       and 32, or in bits, with legal values of 128, 192 and 256. These
       values correspond with Nk values of 4, 6 and 8 respectively.

       The following macros implement a single cycle in the key
       schedule generation process. The number of cycles needed
       for each cx->n_col and nk value is:

        nk =             4  5  6  7  8
        ------------------------------
        cx->n_col = 4   10  9  8  7  7
        cx->n_col = 5   14 11 10  9  9
        cx->n_col = 6   19 15 12 11 11
        cx->n_col = 7   21 19 16 13 14
        cx->n_col = 8   29 23 19 17 14
    */

#if (FUNCS_IN_C & ENC_KEYING_IN_C)

#if defined(AES_128) || defined(AES_VAR)

#define ke4(k,i) \
{   k[4*(i)+4] = ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; \
    k[4*(i)+5] = ss[1] ^= ss[0]; \
    k[4*(i)+6] = ss[2] ^= ss[1]; \
    k[4*(i)+7] = ss[3] ^= ss[2]; \
}

    AES_RETURN aes_encrypt_key128(const unsigned char *key, aes_encrypt_ctx cx[1])
    {
        uint_32t    ss[4];

        cx->ks[0] = ss[0] = word_in(key, 0);
        cx->ks[1] = ss[1] = word_in(key, 1);
        cx->ks[2] = ss[2] = word_in(key, 2);
        cx->ks[3] = ss[3] = word_in(key, 3);

#if ENC_UNROLL == NONE
        {   uint_32t i;
            for (i = 0; i < 9; ++i)
                ke4(cx->ks, i);
        }
#else
        ke4(cx->ks, 0);
        ke4(cx->ks, 1);
        ke4(cx->ks, 2);
        ke4(cx->ks, 3);
        ke4(cx->ks, 4);
        ke4(cx->ks, 5);
        ke4(cx->ks, 6);
        ke4(cx->ks, 7);
        ke4(cx->ks, 8);
#endif
        ke4(cx->ks, 9);
        cx->inf.l = 0;
        cx->inf.b[0] = 10 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_192) || defined(AES_VAR)

#define kef6(k,i) \
{   k[6*(i)+ 6] = ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; \
    k[6*(i)+ 7] = ss[1] ^= ss[0]; \
    k[6*(i)+ 8] = ss[2] ^= ss[1]; \
    k[6*(i)+ 9] = ss[3] ^= ss[2]; \
}

#define ke6(k,i) \
{   kef6(k,i); \
    k[6*(i)+10] = ss[4] ^= ss[3]; \
    k[6*(i)+11] = ss[5] ^= ss[4]; \
}

    AES_RETURN aes_encrypt_key192(const unsigned char *key, aes_encrypt_ctx cx[1])
    {
        uint_32t    ss[6];

        cx->ks[0] = ss[0] = word_in(key, 0);
        cx->ks[1] = ss[1] = word_in(key, 1);
        cx->ks[2] = ss[2] = word_in(key, 2);
        cx->ks[3] = ss[3] = word_in(key, 3);
        cx->ks[4] = ss[4] = word_in(key, 4);
        cx->ks[5] = ss[5] = word_in(key, 5);

#if ENC_UNROLL == NONE
        {   uint_32t i;
            for (i = 0; i < 7; ++i)
                ke6(cx->ks, i);
        }
#else
        ke6(cx->ks, 0);
        ke6(cx->ks, 1);
        ke6(cx->ks, 2);
        ke6(cx->ks, 3);
        ke6(cx->ks, 4);
        ke6(cx->ks, 5);
        ke6(cx->ks, 6);
#endif
        kef6(cx->ks, 7);
        cx->inf.l = 0;
        cx->inf.b[0] = 12 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_256) || defined(AES_VAR)

#define kef8(k,i) \
{   k[8*(i)+ 8] = ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; \
    k[8*(i)+ 9] = ss[1] ^= ss[0]; \
    k[8*(i)+10] = ss[2] ^= ss[1]; \
    k[8*(i)+11] = ss[3] ^= ss[2]; \
}

#define ke8(k,i) \
{   kef8(k,i); \
    k[8*(i)+12] = ss[4] ^= ls_box(ss[3],0); \
    k[8*(i)+13] = ss[5] ^= ss[4]; \
    k[8*(i)+14] = ss[6] ^= ss[5]; \
    k[8*(i)+15] = ss[7] ^= ss[6]; \
}

    AES_RETURN aes_encrypt_key256(const unsigned char *key, aes_encrypt_ctx cx[1])
    {
        uint_32t    ss[8];

        cx->ks[0] = ss[0] = word_in(key, 0);
        cx->ks[1] = ss[1] = word_in(key, 1);
        cx->ks[2] = ss[2] = word_in(key, 2);
        cx->ks[3] = ss[3] = word_in(key, 3);
        cx->ks[4] = ss[4] = word_in(key, 4);
        cx->ks[5] = ss[5] = word_in(key, 5);
        cx->ks[6] = ss[6] = word_in(key, 6);
        cx->ks[7] = ss[7] = word_in(key, 7);

#if ENC_UNROLL == NONE
        {   uint_32t i;
            for (i = 0; i < 6; ++i)
                ke8(cx->ks,  i);
        }
#else
        ke8(cx->ks, 0);
        ke8(cx->ks, 1);
        ke8(cx->ks, 2);
        ke8(cx->ks, 3);
        ke8(cx->ks, 4);
        ke8(cx->ks, 5);
#endif
        kef8(cx->ks, 6);
        cx->inf.l = 0;
        cx->inf.b[0] = 14 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_VAR)

    AES_RETURN aes_encrypt_key(const unsigned char *key, int key_len, aes_encrypt_ctx cx[1])
    {
        switch (key_len)
        {
#if defined( AES_ERR_CHK )
        case 16:
        case 128:
            return aes_encrypt_key128(key, cx);
        case 24:
        case 192:
            return aes_encrypt_key192(key, cx);
        case 32:
        case 256:
            return aes_encrypt_key256(key, cx);
        default:
            return EXIT_FAILURE;
#else
        case 16:
        case 128:
            aes_encrypt_key128(key, cx);
            return;
        case 24:
        case 192:
            aes_encrypt_key192(key, cx);
            return;
        case 32:
        case 256:
            aes_encrypt_key256(key, cx);
            return;
#endif
        }
    }

#endif

#endif

#if (FUNCS_IN_C & DEC_KEYING_IN_C)

    /* this is used to store the decryption round keys  */
    /* in forward or reverse order                      */

#ifdef AES_REV_DKS
#define v(n,i)  ((n) - (i) + 2 * ((i) & 3))
#else
#define v(n,i)  (i)
#endif

#if DEC_ROUND == NO_TABLES
#define ff(x)   (x)
#else
#define ff(x)   inv_mcol(x)
#if defined( dec_imvars )
#define d_vars  dec_imvars
#endif
#endif

#if defined(AES_128) || defined(AES_VAR)

#define k4e(k,i) \
{   k[v(40,(4*(i))+4)] = ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; \
    k[v(40,(4*(i))+5)] = ss[1] ^= ss[0]; \
    k[v(40,(4*(i))+6)] = ss[2] ^= ss[1]; \
    k[v(40,(4*(i))+7)] = ss[3] ^= ss[2]; \
}

#if 1

#define kdf4(k,i) \
{   ss[0] = ss[0] ^ ss[2] ^ ss[1] ^ ss[3]; \
    ss[1] = ss[1] ^ ss[3]; \
    ss[2] = ss[2] ^ ss[3]; \
    ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; \
    ss[i % 4] ^= ss[4]; \
    ss[4] ^= k[v(40,(4*(i)))];   k[v(40,(4*(i))+4)] = ff(ss[4]); \
    ss[4] ^= k[v(40,(4*(i))+1)]; k[v(40,(4*(i))+5)] = ff(ss[4]); \
    ss[4] ^= k[v(40,(4*(i))+2)]; k[v(40,(4*(i))+6)] = ff(ss[4]); \
    ss[4] ^= k[v(40,(4*(i))+3)]; k[v(40,(4*(i))+7)] = ff(ss[4]); \
}

#define kd4(k,i) \
{   ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; \
    ss[i % 4] ^= ss[4]; ss[4] = ff(ss[4]); \
    k[v(40,(4*(i))+4)] = ss[4] ^= k[v(40,(4*(i)))]; \
    k[v(40,(4*(i))+5)] = ss[4] ^= k[v(40,(4*(i))+1)]; \
    k[v(40,(4*(i))+6)] = ss[4] ^= k[v(40,(4*(i))+2)]; \
    k[v(40,(4*(i))+7)] = ss[4] ^= k[v(40,(4*(i))+3)]; \
}

#define kdl4(k,i) \
{   ss[4] = ls_box(ss[(i+3) % 4], 3) ^ t_use(r,c)[i]; ss[i % 4] ^= ss[4]; \
    k[v(40,(4*(i))+4)] = (ss[0] ^= ss[1]) ^ ss[2] ^ ss[3]; \
    k[v(40,(4*(i))+5)] = ss[1] ^ ss[3]; \
    k[v(40,(4*(i))+6)] = ss[0]; \
    k[v(40,(4*(i))+7)] = ss[1]; \
}

#else

#define kdf4(k,i) \
{   ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[v(40,(4*(i))+ 4)] = ff(ss[0]); \
    ss[1] ^= ss[0]; k[v(40,(4*(i))+ 5)] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[v(40,(4*(i))+ 6)] = ff(ss[2]); \
    ss[3] ^= ss[2]; k[v(40,(4*(i))+ 7)] = ff(ss[3]); \
}

#define kd4(k,i) \
{   ss[4] = ls_box(ss[3],3) ^ t_use(r,c)[i]; \
    ss[0] ^= ss[4]; ss[4] = ff(ss[4]); k[v(40,(4*(i))+ 4)] = ss[4] ^= k[v(40,(4*(i)))]; \
    ss[1] ^= ss[0]; k[v(40,(4*(i))+ 5)] = ss[4] ^= k[v(40,(4*(i))+ 1)]; \
    ss[2] ^= ss[1]; k[v(40,(4*(i))+ 6)] = ss[4] ^= k[v(40,(4*(i))+ 2)]; \
    ss[3] ^= ss[2]; k[v(40,(4*(i))+ 7)] = ss[4] ^= k[v(40,(4*(i))+ 3)]; \
}

#define kdl4(k,i) \
{   ss[0] ^= ls_box(ss[3],3) ^ t_use(r,c)[i]; k[v(40,(4*(i))+ 4)] = ss[0]; \
    ss[1] ^= ss[0]; k[v(40,(4*(i))+ 5)] = ss[1]; \
    ss[2] ^= ss[1]; k[v(40,(4*(i))+ 6)] = ss[2]; \
    ss[3] ^= ss[2]; k[v(40,(4*(i))+ 7)] = ss[3]; \
}

#endif

    AES_RETURN aes_decrypt_key128(const unsigned char *key, aes_decrypt_ctx cx[1])
    {
        uint_32t    ss[5];
#if defined( d_vars )
        d_vars;
#endif
        cx->ks[v(40,(0))] = ss[0] = word_in(key, 0);
        cx->ks[v(40,(1))] = ss[1] = word_in(key, 1);
        cx->ks[v(40,(2))] = ss[2] = word_in(key, 2);
        cx->ks[v(40,(3))] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
        {   uint_32t i;
            for (i = 0; i < 10; ++i)
                k4e(cx->ks, i);
#if !(DEC_ROUND == NO_TABLES)
            for (i = N_COLS; i < 10 * N_COLS; ++i)
                cx->ks[i] = inv_mcol(cx->ks[i]);
#endif
        }
#else
        kdf4(cx->ks, 0);
        kd4(cx->ks, 1);
        kd4(cx->ks, 2);
        kd4(cx->ks, 3);
        kd4(cx->ks, 4);
        kd4(cx->ks, 5);
        kd4(cx->ks, 6);
        kd4(cx->ks, 7);
        kd4(cx->ks, 8);
        kdl4(cx->ks, 9);
#endif
        cx->inf.l = 0;
        cx->inf.b[0] = 10 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_192) || defined(AES_VAR)

#define k6ef(k,i) \
{   k[v(48,(6*(i))+ 6)] = ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; \
    k[v(48,(6*(i))+ 7)] = ss[1] ^= ss[0]; \
    k[v(48,(6*(i))+ 8)] = ss[2] ^= ss[1]; \
    k[v(48,(6*(i))+ 9)] = ss[3] ^= ss[2]; \
}

#define k6e(k,i) \
{   k6ef(k,i); \
    k[v(48,(6*(i))+10)] = ss[4] ^= ss[3]; \
    k[v(48,(6*(i))+11)] = ss[5] ^= ss[4]; \
}

#define kdf6(k,i) \
{   ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[v(48,(6*(i))+ 6)] = ff(ss[0]); \
    ss[1] ^= ss[0]; k[v(48,(6*(i))+ 7)] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[v(48,(6*(i))+ 8)] = ff(ss[2]); \
    ss[3] ^= ss[2]; k[v(48,(6*(i))+ 9)] = ff(ss[3]); \
    ss[4] ^= ss[3]; k[v(48,(6*(i))+10)] = ff(ss[4]); \
    ss[5] ^= ss[4]; k[v(48,(6*(i))+11)] = ff(ss[5]); \
}

#define kd6(k,i) \
{   ss[6] = ls_box(ss[5],3) ^ t_use(r,c)[i]; \
    ss[0] ^= ss[6]; ss[6] = ff(ss[6]); k[v(48,(6*(i))+ 6)] = ss[6] ^= k[v(48,(6*(i)))]; \
    ss[1] ^= ss[0]; k[v(48,(6*(i))+ 7)] = ss[6] ^= k[v(48,(6*(i))+ 1)]; \
    ss[2] ^= ss[1]; k[v(48,(6*(i))+ 8)] = ss[6] ^= k[v(48,(6*(i))+ 2)]; \
    ss[3] ^= ss[2]; k[v(48,(6*(i))+ 9)] = ss[6] ^= k[v(48,(6*(i))+ 3)]; \
    ss[4] ^= ss[3]; k[v(48,(6*(i))+10)] = ss[6] ^= k[v(48,(6*(i))+ 4)]; \
    ss[5] ^= ss[4]; k[v(48,(6*(i))+11)] = ss[6] ^= k[v(48,(6*(i))+ 5)]; \
}

#define kdl6(k,i) \
{   ss[0] ^= ls_box(ss[5],3) ^ t_use(r,c)[i]; k[v(48,(6*(i))+ 6)] = ss[0]; \
    ss[1] ^= ss[0]; k[v(48,(6*(i))+ 7)] = ss[1]; \
    ss[2] ^= ss[1]; k[v(48,(6*(i))+ 8)] = ss[2]; \
    ss[3] ^= ss[2]; k[v(48,(6*(i))+ 9)] = ss[3]; \
}

    AES_RETURN aes_decrypt_key192(const unsigned char *key, aes_decrypt_ctx cx[1])
    {
        uint_32t    ss[7];
#if defined( d_vars )
        d_vars;
#endif
        cx->ks[v(48,(0))] = ss[0] = word_in(key, 0);
        cx->ks[v(48,(1))] = ss[1] = word_in(key, 1);
        cx->ks[v(48,(2))] = ss[2] = word_in(key, 2);
        cx->ks[v(48,(3))] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
        cx->ks[v(48,(4))] = ss[4] = word_in(key, 4);
        cx->ks[v(48,(5))] = ss[5] = word_in(key, 5);
        {
            uint_32t i;

            for (i = 0; i < 7; ++i)
                k6e(cx->ks, i);
            k6ef(cx->ks, 7);
#if !(DEC_ROUND == NO_TABLES)
            for (i = N_COLS; i < 12 * N_COLS; ++i)
                cx->ks[i] = inv_mcol(cx->ks[i]);
#endif
        }
#else
        cx->ks[v(48,(4))] = ff(ss[4] = word_in(key, 4));
        cx->ks[v(48,(5))] = ff(ss[5] = word_in(key, 5));
        kdf6(cx->ks, 0);
        kd6(cx->ks, 1);
        kd6(cx->ks, 2);
        kd6(cx->ks, 3);
        kd6(cx->ks, 4);
        kd6(cx->ks, 5);
        kd6(cx->ks, 6);
        kdl6(cx->ks, 7);
#endif
        cx->inf.l = 0;
        cx->inf.b[0] = 12 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_256) || defined(AES_VAR)

#define k8ef(k,i) \
{   k[v(56,(8*(i))+ 8)] = ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; \
    k[v(56,(8*(i))+ 9)] = ss[1] ^= ss[0]; \
    k[v(56,(8*(i))+10)] = ss[2] ^= ss[1]; \
    k[v(56,(8*(i))+11)] = ss[3] ^= ss[2]; \
}

#define k8e(k,i) \
{   k8ef(k,i); \
    k[v(56,(8*(i))+12)] = ss[4] ^= ls_box(ss[3],0); \
    k[v(56,(8*(i))+13)] = ss[5] ^= ss[4]; \
    k[v(56,(8*(i))+14)] = ss[6] ^= ss[5]; \
    k[v(56,(8*(i))+15)] = ss[7] ^= ss[6]; \
}

#define kdf8(k,i) \
{   ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[v(56,(8*(i))+ 8)] = ff(ss[0]); \
    ss[1] ^= ss[0]; k[v(56,(8*(i))+ 9)] = ff(ss[1]); \
    ss[2] ^= ss[1]; k[v(56,(8*(i))+10)] = ff(ss[2]); \
    ss[3] ^= ss[2]; k[v(56,(8*(i))+11)] = ff(ss[3]); \
    ss[4] ^= ls_box(ss[3],0); k[v(56,(8*(i))+12)] = ff(ss[4]); \
    ss[5] ^= ss[4]; k[v(56,(8*(i))+13)] = ff(ss[5]); \
    ss[6] ^= ss[5]; k[v(56,(8*(i))+14)] = ff(ss[6]); \
    ss[7] ^= ss[6]; k[v(56,(8*(i))+15)] = ff(ss[7]); \
}

#define kd8(k,i) \
{   ss[8] = ls_box(ss[7],3) ^ t_use(r,c)[i]; \
    ss[0] ^= ss[8]; ss[8] = ff(ss[8]); k[v(56,(8*(i))+ 8)] = ss[8] ^= k[v(56,(8*(i)))]; \
    ss[1] ^= ss[0]; k[v(56,(8*(i))+ 9)] = ss[8] ^= k[v(56,(8*(i))+ 1)]; \
    ss[2] ^= ss[1]; k[v(56,(8*(i))+10)] = ss[8] ^= k[v(56,(8*(i))+ 2)]; \
    ss[3] ^= ss[2]; k[v(56,(8*(i))+11)] = ss[8] ^= k[v(56,(8*(i))+ 3)]; \
    ss[8] = ls_box(ss[3],0); \
    ss[4] ^= ss[8]; ss[8] = ff(ss[8]); k[v(56,(8*(i))+12)] = ss[8] ^= k[v(56,(8*(i))+ 4)]; \
    ss[5] ^= ss[4]; k[v(56,(8*(i))+13)] = ss[8] ^= k[v(56,(8*(i))+ 5)]; \
    ss[6] ^= ss[5]; k[v(56,(8*(i))+14)] = ss[8] ^= k[v(56,(8*(i))+ 6)]; \
    ss[7] ^= ss[6]; k[v(56,(8*(i))+15)] = ss[8] ^= k[v(56,(8*(i))+ 7)]; \
}

#define kdl8(k,i) \
{   ss[0] ^= ls_box(ss[7],3) ^ t_use(r,c)[i]; k[v(56,(8*(i))+ 8)] = ss[0]; \
    ss[1] ^= ss[0]; k[v(56,(8*(i))+ 9)] = ss[1]; \
    ss[2] ^= ss[1]; k[v(56,(8*(i))+10)] = ss[2]; \
    ss[3] ^= ss[2]; k[v(56,(8*(i))+11)] = ss[3]; \
}

    AES_RETURN aes_decrypt_key256(const unsigned char *key, aes_decrypt_ctx cx[1])
    {
        uint_32t    ss[9];
#if defined( d_vars )
        d_vars;
#endif
        cx->ks[v(56,(0))] = ss[0] = word_in(key, 0);
        cx->ks[v(56,(1))] = ss[1] = word_in(key, 1);
        cx->ks[v(56,(2))] = ss[2] = word_in(key, 2);
        cx->ks[v(56,(3))] = ss[3] = word_in(key, 3);

#if DEC_UNROLL == NONE
        cx->ks[v(56,(4))] = ss[4] = word_in(key, 4);
        cx->ks[v(56,(5))] = ss[5] = word_in(key, 5);
        cx->ks[v(56,(6))] = ss[6] = word_in(key, 6);
        cx->ks[v(56,(7))] = ss[7] = word_in(key, 7);
        {
            uint_32t i;

            for (i = 0; i < 6; ++i)
                k8e(cx->ks,  i);
            k8ef(cx->ks,  6);
#if !(DEC_ROUND == NO_TABLES)
            for (i = N_COLS; i < 14 * N_COLS; ++i)
                cx->ks[i] = inv_mcol(cx->ks[i]);

#endif
        }
#else
        cx->ks[v(56,(4))] = ff(ss[4] = word_in(key, 4));
        cx->ks[v(56,(5))] = ff(ss[5] = word_in(key, 5));
        cx->ks[v(56,(6))] = ff(ss[6] = word_in(key, 6));
        cx->ks[v(56,(7))] = ff(ss[7] = word_in(key, 7));
        kdf8(cx->ks, 0);
        kd8(cx->ks, 1);
        kd8(cx->ks, 2);
        kd8(cx->ks, 3);
        kd8(cx->ks, 4);
        kd8(cx->ks, 5);
        kdl8(cx->ks, 6);
#endif
        cx->inf.l = 0;
        cx->inf.b[0] = 14 * 16;

#ifdef USE_VIA_ACE_IF_PRESENT
        if (VIA_ACE_AVAILABLE)
            cx->inf.b[1] = 0xff;
#endif

#if defined( AES_ERR_CHK )
        return EXIT_SUCCESS;
#endif
    }

#endif

#if defined(AES_VAR)

    AES_RETURN aes_decrypt_key(const unsigned char *key, int key_len, aes_decrypt_ctx cx[1])
    {
        switch (key_len)
        {
#if defined( AES_ERR_CHK )
        case 16:
        case 128:
            return aes_decrypt_key128(key, cx);
        case 24:
        case 192:
            return aes_decrypt_key192(key, cx);
        case 32:
        case 256:
            return aes_decrypt_key256(key, cx);
        default:
            return EXIT_FAILURE;
#else
        case 16:
        case 128:
            aes_decrypt_key128(key, cx);
            return;
        case 24:
        case 192:
            aes_decrypt_key192(key, cx);
            return;
        case 32:
        case 256:
            aes_decrypt_key256(key, cx);
            return;
#endif
        }
    }

#endif

#endif

#if defined(__cplusplus)
}
#endif


/*
 * Aescrypt.c
 */
/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007
*/

#include "Aesopt.h"
#include "Aestab.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#define si(y,x,k,c) (s(y,c) = word_in(x, c) ^ (k)[c])
#define so(y,x,c)   word_out(y, c, s(x,c))

#if defined(ARRAYS)
#define locals(y,x)     x[4],y[4]
#else
#define locals(y,x)     x##0,x##1,x##2,x##3,y##0,y##1,y##2,y##3
#endif

#define l_copy(y, x)    s(y,0) = s(x,0); s(y,1) = s(x,1); \
                        s(y,2) = s(x,2); s(y,3) = s(x,3);
#define state_in(y,x,k) si(y,x,k,0); si(y,x,k,1); si(y,x,k,2); si(y,x,k,3)
#define state_out(y,x)  so(y,x,0); so(y,x,1); so(y,x,2); so(y,x,3)
#define round(rm,y,x,k) rm(y,x,k,0); rm(y,x,k,1); rm(y,x,k,2); rm(y,x,k,3)

#if ( FUNCS_IN_C & ENCRYPTION_IN_C )

/* Visual C++ .Net v7.1 provides the fastest encryption code when using
   Pentium optimiation with small code but this is poor for decryption
   so we need to control this with the following VC++ pragmas
*/

#if defined( _MSC_VER ) && !defined( _WIN64 )
#pragma optimize( "s", on )
#endif

/* Given the column (c) of the output state variable, the following
   macros give the input state variables which are needed in its
   computation for each row (r) of the state. All the alternative
   macros give the same end values but expand into different ways
   of calculating these values.  In particular the complex macro
   used for dynamically variable block sizes is designed to expand
   to a compile time constant whenever possible but will expand to
   conditional clauses on some branches (I am grateful to Frank
   Yellin for this construction)
*/

#define fwd_var(x,r,c)\
 ( r == 0 ? ( c == 0 ? s(x,0) : c == 1 ? s(x,1) : c == 2 ? s(x,2) : s(x,3))\
 : r == 1 ? ( c == 0 ? s(x,1) : c == 1 ? s(x,2) : c == 2 ? s(x,3) : s(x,0))\
 : r == 2 ? ( c == 0 ? s(x,2) : c == 1 ? s(x,3) : c == 2 ? s(x,0) : s(x,1))\
 :          ( c == 0 ? s(x,3) : c == 1 ? s(x,0) : c == 2 ? s(x,1) : s(x,2)))

#if defined(FT4_SET)
#undef  dec_fmvars
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ four_tables(x,t_use(f,n),fwd_var,rf1,c))
#elif defined(FT1_SET)
#undef  dec_fmvars
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ one_table(x,upr,t_use(f,n),fwd_var,rf1,c))
#else
#define fwd_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ fwd_mcol(no_table(x,t_use(s,box),fwd_var,rf1,c)))
#endif

#if defined(FL4_SET)
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ four_tables(x,t_use(f,l),fwd_var,rf1,c))
#elif defined(FL1_SET)
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ one_table(x,ups,t_use(f,l),fwd_var,rf1,c))
#else
#define fwd_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ no_table(x,t_use(s,box),fwd_var,rf1,c))
#endif

AES_RETURN aes_encrypt(const unsigned char *in, unsigned char *out, const aes_encrypt_ctx cx[1])
{   uint_32t         locals(b0, b1);
    const uint_32t   *kp;
#if defined( dec_fmvars )
    dec_fmvars; /* declare variables for fwd_mcol() if needed */
#endif

#if defined( AES_ERR_CHK )
    if( cx->inf.b[0] != 10 * 16 && cx->inf.b[0] != 12 * 16 && cx->inf.b[0] != 14 * 16 )
        return EXIT_FAILURE;
#endif

    kp = cx->ks;
    state_in(b0, in, kp);

#if (ENC_UNROLL == FULL)

    switch(cx->inf.b[0])
    {
    case 14 * 16:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        kp += 2 * N_COLS;
    case 12 * 16:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        kp += 2 * N_COLS;
    case 10 * 16:
        round(fwd_rnd,  b1, b0, kp + 1 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 2 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 3 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 4 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 5 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 6 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 7 * N_COLS);
        round(fwd_rnd,  b0, b1, kp + 8 * N_COLS);
        round(fwd_rnd,  b1, b0, kp + 9 * N_COLS);
        round(fwd_lrnd, b0, b1, kp +10 * N_COLS);
    }

#else

#if (ENC_UNROLL == PARTIAL)
    {   uint_32t    rnd;
        for(rnd = 0; rnd < (cx->inf.b[0] >> 5) - 1; ++rnd)
        {
            kp += N_COLS;
            round(fwd_rnd, b1, b0, kp);
            kp += N_COLS;
            round(fwd_rnd, b0, b1, kp);
        }
        kp += N_COLS;
        round(fwd_rnd,  b1, b0, kp);
#else
    {   uint_32t    rnd;
        for(rnd = 0; rnd < (cx->inf.b[0] >> 4) - 1; ++rnd)
        {
            kp += N_COLS;
            round(fwd_rnd, b1, b0, kp);
            l_copy(b0, b1);
        }
#endif
        kp += N_COLS;
        round(fwd_lrnd, b0, b1, kp);
    }
#endif

    state_out(out, b0);

#if defined( AES_ERR_CHK )
    return EXIT_SUCCESS;
#endif
}

#endif

#if ( FUNCS_IN_C & DECRYPTION_IN_C)

/* Visual C++ .Net v7.1 provides the fastest encryption code when using
   Pentium optimiation with small code but this is poor for decryption
   so we need to control this with the following VC++ pragmas
*/

#if defined( _MSC_VER ) && !defined( _WIN64 )
#pragma optimize( "t", on )
#endif

/* Given the column (c) of the output state variable, the following
   macros give the input state variables which are needed in its
   computation for each row (r) of the state. All the alternative
   macros give the same end values but expand into different ways
   of calculating these values.  In particular the complex macro
   used for dynamically variable block sizes is designed to expand
   to a compile time constant whenever possible but will expand to
   conditional clauses on some branches (I am grateful to Frank
   Yellin for this construction)
*/

#define inv_var(x,r,c)\
 ( r == 0 ? ( c == 0 ? s(x,0) : c == 1 ? s(x,1) : c == 2 ? s(x,2) : s(x,3))\
 : r == 1 ? ( c == 0 ? s(x,3) : c == 1 ? s(x,0) : c == 2 ? s(x,1) : s(x,2))\
 : r == 2 ? ( c == 0 ? s(x,2) : c == 1 ? s(x,3) : c == 2 ? s(x,0) : s(x,1))\
 :          ( c == 0 ? s(x,1) : c == 1 ? s(x,2) : c == 2 ? s(x,3) : s(x,0)))

#if defined(IT4_SET)
#undef  dec_imvars
#define inv_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ four_tables(x,t_use(i,n),inv_var,rf1,c))
#elif defined(IT1_SET)
#undef  dec_imvars
#define inv_rnd(y,x,k,c)    (s(y,c) = (k)[c] ^ one_table(x,upr,t_use(i,n),inv_var,rf1,c))
#else
#define inv_rnd(y,x,k,c)    (s(y,c) = inv_mcol((k)[c] ^ no_table(x,t_use(i,box),inv_var,rf1,c)))
#endif

#if defined(IL4_SET)
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ four_tables(x,t_use(i,l),inv_var,rf1,c))
#elif defined(IL1_SET)
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ one_table(x,ups,t_use(i,l),inv_var,rf1,c))
#else
#define inv_lrnd(y,x,k,c)   (s(y,c) = (k)[c] ^ no_table(x,t_use(i,box),inv_var,rf1,c))
#endif

/* This code can work with the decryption key schedule in the   */
/* order that is used for encrytpion (where the 1st decryption  */
/* round key is at the high end ot the schedule) or with a key  */
/* schedule that has been reversed to put the 1st decryption    */
/* round key at the low end of the schedule in memory (when     */
/* AES_REV_DKS is defined)                                      */

#ifdef AES_REV_DKS
#define key_ofs     0
#define rnd_key(n)  (kp + n * N_COLS)
#else
#define key_ofs     1
#define rnd_key(n)  (kp - n * N_COLS)
#endif

AES_RETURN aes_decrypt(const unsigned char *in, unsigned char *out, const aes_decrypt_ctx cx[1])
{   uint_32t        locals(b0, b1);
#if defined( dec_imvars )
    dec_imvars; /* declare variables for inv_mcol() if needed */
#endif
    const uint_32t *kp;

#if defined( AES_ERR_CHK )
    if( cx->inf.b[0] != 10 * 16 && cx->inf.b[0] != 12 * 16 && cx->inf.b[0] != 14 * 16 )
        return EXIT_FAILURE;
#endif

    kp = cx->ks + (key_ofs ? (cx->inf.b[0] >> 2) : 0);
    state_in(b0, in, kp);

#if (DEC_UNROLL == FULL)

    kp = cx->ks + (key_ofs ? 0 : (cx->inf.b[0] >> 2));
    switch(cx->inf.b[0])
    {
    case 14 * 16:
        round(inv_rnd,  b1, b0, rnd_key(-13));
        round(inv_rnd,  b0, b1, rnd_key(-12));
    case 12 * 16:
        round(inv_rnd,  b1, b0, rnd_key(-11));
        round(inv_rnd,  b0, b1, rnd_key(-10));
    case 10 * 16:
        round(inv_rnd,  b1, b0, rnd_key(-9));
        round(inv_rnd,  b0, b1, rnd_key(-8));
        round(inv_rnd,  b1, b0, rnd_key(-7));
        round(inv_rnd,  b0, b1, rnd_key(-6));
        round(inv_rnd,  b1, b0, rnd_key(-5));
        round(inv_rnd,  b0, b1, rnd_key(-4));
        round(inv_rnd,  b1, b0, rnd_key(-3));
        round(inv_rnd,  b0, b1, rnd_key(-2));
        round(inv_rnd,  b1, b0, rnd_key(-1));
        round(inv_lrnd, b0, b1, rnd_key( 0));
    }

#else

#if (DEC_UNROLL == PARTIAL)
    {   uint_32t    rnd;
        for(rnd = 0; rnd < (cx->inf.b[0] >> 5) - 1; ++rnd)
        {
            kp = rnd_key(1);
            round(inv_rnd, b1, b0, kp);
            kp = rnd_key(1);
            round(inv_rnd, b0, b1, kp);
        }
        kp = rnd_key(1);
        round(inv_rnd, b1, b0, kp);
#else
    {   uint_32t    rnd;
        for(rnd = 0; rnd < (cx->inf.b[0] >> 4) - 1; ++rnd)
        {
            kp = rnd_key(1);
            round(inv_rnd, b1, b0, kp);
            l_copy(b0, b1);
        }
#endif
        kp = rnd_key(1);
        round(inv_lrnd, b0, b1, kp);
        }
#endif

    state_out(out, b0);

#if defined( AES_ERR_CHK )
    return EXIT_SUCCESS;
#endif
}

#endif

#if defined(__cplusplus)
}
#endif
