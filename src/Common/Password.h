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
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef PASSWORD_H
#define PASSWORD_H

// User text input limits
#define MIN_PASSWORD			1		// Minimum possible password length
#define MAX_PASSWORD			64		// Maximum possible password length

#define PASSWORD_LEN_WARNING	20		// Display a warning when a password is shorter than this

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	// Modifying this structure can introduce incompatibility with previous versions
	unsigned __int32 Length;
	unsigned char Text[MAX_PASSWORD + 1];
	char Pad[3]; // keep 64-bit alignment
} Password;

#if defined(_WIN32) && !defined(TC_WINDOWS_DRIVER)

void VerifyPasswordAndUpdate ( HWND hwndDlg , HWND hButton , HWND hPassword , HWND hVerify , unsigned char *szPassword , char *szVerify, BOOL keyFilesEnabled );
BOOL CheckPasswordLength (HWND hwndDlg, HWND hwndItem);		
BOOL CheckPasswordCharEncoding (HWND hPassword, Password *ptrPw);			
int ChangePwd (char *lpszVolume, Password *oldPassword, Password *newPassword, int pkcs5, HWND hwndDlg);

#endif	// defined(_WIN32) && !defined(TC_WINDOWS_DRIVER)

#ifdef __cplusplus
}
#endif

#endif	// PASSWORD_H
