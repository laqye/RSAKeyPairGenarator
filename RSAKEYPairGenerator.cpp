// RSAKEYPairGenerator.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include<stdio.h>
#include <tchar.h>
#include <windows.h>

#define KEYLENGTH 0x08000000 * 2


int acquireContext(HCRYPTPROV* phCryptProv) {

	BYTE ProviderStr[] = { "Microsoft Enhanced RSA and AES Cryptographic Provider" };

	if (CryptAcquireContextA(phCryptProv, 0, (LPCSTR)ProviderStr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (CryptAcquireContextA(phCryptProv, 0, (LPCSTR)ProviderStr, PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}

	BYTE PrototypeStr[] = { "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)" };
	

	if (CryptAcquireContextA(phCryptProv, 0, (LPCSTR)PrototypeStr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (CryptAcquireContextA(phCryptProv, 0, (LPCSTR)PrototypeStr, PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}
	return 0;
}

int main()
{
	HCRYPTPROV hprov;
	HCRYPTKEY hKey;

	DWORD byteread = 0;
	const size_t byewritten = 2048;
	CHAR buff[byewritten];

	if (acquireContext(&hprov) == -1) {
		return -1;
	}

	HANDLE hFile;
	HANDLE hFile2;
	hFile = CreateFileA("PUBLICKEY.TXT", GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}

	hFile2 = CreateFileA("PRIVATEKEY.TXT", GENERIC_ALL, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	DWORD size = 0;
	//veriables for publicKey
	HCRYPTKEY hPublicKey = NULL;
	DWORD dwPublicKeyLen = 0;
	BYTE* pbPublicKey = NULL;
	LPBYTE pPublicKeyBLOB = (LPBYTE)LocalAlloc(0, size);
	DWORD byteWrite = 0;
	DWORD byteWrite2 = 0;

	//veriables for privateKey
	HCRYPTKEY hPrivateKey = NULL;
	DWORD dwPrivateKeyLen = 0;
	BYTE* pbPrivateKey = NULL;
	LPBYTE pPrivateKeyBLOB = (LPBYTE)LocalAlloc(0, size);
	if (acquireContext(&hprov) == -1) {
		return -1;
	}
	//key pair generation
	if (!CryptGenKey(hprov, AT_KEYEXCHANGE, KEYLENGTH | CRYPT_EXPORTABLE, &hKey)) {
		_tprintf(TEXT("failed generating KeyPair %x. \n"), GetLastError());
	}
	//Get publicKey size
	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
		_tprintf(TEXT("failed getting pubkeySize %x. \n"), GetLastError());
	}
	//Allocate for publicKey
	pbPublicKey = (BYTE*)calloc(dwPublicKeyLen, 1);
	if (!pbPublicKey) {
		free(pbPublicKey);
	}

	//GetPublicKey
	if (!CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
		_tprintf(TEXT("failed getting pubKey %x. \n"), GetLastError());
	}
	if (WriteFile(hFile, pbPublicKey, dwPublicKeyLen, &byteWrite, NULL) == FALSE) {
		_tprintf(TEXT("failed writing to file %x. \n"), GetLastError());
	}



	//Get privateKey size
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwPrivateKeyLen)) {
		_tprintf(TEXT("failed getting prkeySize %x. \n"), GetLastError());
	}
	//Allocate for privateKey
	pbPrivateKey = (BYTE*)calloc(dwPrivateKeyLen, 1);
	if (!pbPrivateKey) {
		free(pbPrivateKey);
	}


	//GetPrivateKey
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbPrivateKey, &dwPrivateKeyLen)) {
		_tprintf(TEXT("failed getting privatekey %x. \n"), GetLastError());
	}
	if (WriteFile(hFile2, pbPrivateKey, dwPrivateKeyLen, &byteWrite2, NULL) == FALSE) {
		_tprintf(TEXT("Error writing to file %x. \n"), GetLastError());
	}

	LocalFree(pPublicKeyBLOB);
	LocalFree(pPrivateKeyBLOB);
	if (hprov) {
		CryptReleaseContext(hprov, 0);
	}
	if (hFile) {
		CloseHandle(hFile);
	}
	if (hFile2) {
		CloseHandle(hFile2);
	}

	return 0;



}
