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
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2010 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#include "Tcdefs.h"

#ifndef TC_WINDOWS_BOOT
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <time.h>
//#include "EncryptionThreadPool.h"
#endif

#include <stddef.h>
#include <string.h>
#include <stdio.h>

//#ifndef DEVICE_DRIVER
//#include "Random.h"
//#endif

#include "Volumes.h"
//#include "Apidrvr.h"

/* Volume header v5 structure (used since TrueCrypt 7.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Reserved (set to zero)
// 84		8		Reserved (set to zero)
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes, valid if field 70 >= 0x600 or flag bit 0 == 1)
// 108		8		Byte offset of the start of the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 116		8		Size of the encrypted area within the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 124		4		Flags: bit 0 set = system encryption; bit 1 set = non-system in-place encryption, bits 2-31 are reserved (set to zero)
// 128		4		Sector size in bytes
// 132		120		Reserved (set to zero)
// 252		4		CRC-32 checksum of the (decrypted) bytes 64-251
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v4 structure (used by TrueCrypt 6.x): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Reserved (set to zero)
// 84		8		Reserved (set to zero)
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes, valid if field 70 >= 0x600 or flag bit 0 == 1)
// 108		8		Byte offset of the start of the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 116		8		Size of the encrypted area within the master key scope (valid if field 70 >= 0x600 or flag bit 0 == 1)
// 124		4		Flags: bit 0 set = system encryption; bit 1 set = non-system in-place encryption, bits 2-31 are reserved
// 128		124		Reserved (set to zero)
// 252		4		CRC-32 checksum of the (decrypted) bytes 64-251
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v3 structure (used by TrueCrypt 5.x): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		8		Size of the volume in bytes (identical with field 92 for hidden volumes)
// 108		8		Start byte offset of the encrypted area of the volume
// 116		8		Size of the encrypted area of the volume in bytes
// 124		132		Reserved (set to zero)
// 256		256		Concatenated primary master key(s) and secondary master key(s) (XTS mode)


/* Deprecated/legacy volume header v2 structure (used before TrueCrypt 5.0): */
//
// Offset	Length	Description
// ------------------------------------------
// Unencrypted:
// 0		64		Salt
// Encrypted:
// 64		4		ASCII string 'TRUE'
// 68		2		Header version
// 70		2		Required program version
// 72		4		CRC-32 checksum of the (decrypted) bytes 256-511
// 76		8		Volume creation time
// 84		8		Header creation time
// 92		8		Size of hidden volume in bytes (0 = normal volume)
// 100		156		Reserved (set to zero)
// 256		32		For LRW (deprecated/legacy), secondary key
//					For CBC (deprecated/legacy), data used to generate IV and whitening values
// 288		224		Master key(s)



uint16 GetHeaderField16 (byte *header, int offset)
{
	return BE16 (*(uint16 *) (header + offset));
}


uint32 GetHeaderField32 (byte *header, int offset)
{
	return BE32 (*(uint32 *) (header + offset));
}


UINT64_STRUCT GetHeaderField64 (byte *header, int offset)
{
	UINT64_STRUCT uint64Struct;

#ifndef TC_NO_COMPILER_INT64
	uint64Struct.Value = BE64 (*(uint64 *) (header + offset));
#else
	uint64Struct.HighPart = BE32 (*(uint32 *) (header + offset));
	uint64Struct.LowPart = BE32 (*(uint32 *) (header + offset + 4));
#endif
	return uint64Struct;
}


