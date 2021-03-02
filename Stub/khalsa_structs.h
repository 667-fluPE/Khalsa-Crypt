#include <Windows.h>
#include <wincrypt.h>
#include <winternl.h>

typedef struct _RTLP_CURDIR_REF
{
	LONG RefCount;
	HANDLE Handle;
} RTLP_CURDIR_REF, * PRTLP_CURDIR_REF;


typedef struct RTL_RELATIVE_NAME_U {
	UNICODE_STRING RelativeName;
	HANDLE ContainingDirectory;
	PRTLP_CURDIR_REF CurDirRef;
} RTL_RELATIVE_NAME_U, * PRTL_RELATIVE_NAME_U;


typedef struct _FILE_RENAME_INFORMATION
{
	BOOLEAN	ReplaceIfExists;
	HANDLE	RootDirectory;
	ULONG	FileNameLength;
	WCHAR	FileName[1];
} FILE_RENAME_INFORMATION, * PFILE_RENAME_INFORMATION;



typedef struct _FILE_BOTH_DIR_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			FileIndex;
	LARGE_INTEGER	CreationTime;
	LARGE_INTEGER	LastAccessTime;
	LARGE_INTEGER	LastWriteTime;
	LARGE_INTEGER	ChangeTime;
	LARGE_INTEGER	EndOfFile;
	LARGE_INTEGER	AllocationSize;
	ULONG			FileAttributes;
	ULONG			FileNameLength;
	ULONG			EaSize;
	CCHAR			ShortNameLength;
	WCHAR			ShortName[12];
	WCHAR			FileName[1];
} FILE_BOTH_DIR_INFORMATION, * PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	WCHAR         FileName[1];
} FILE_FULL_DIR_INFORMATION, * PFILE_FULL_DIR_INFORMATION;

typedef struct _PROCESS_DEVICEMAP_INFORMATION
{
	union
	{
		struct
		{
			HANDLE DirectoryHandle;
		} Set;
		struct
		{
			ULONG DriveMap;
			UCHAR DriveType[32];
		} Query;
	};
} PROCESS_DEVICEMAP_INFORMATION, * PPROCESS_DEVICEMAP_INFORMATION;


typedef enum _OBJECT_WAIT_TYPE {




	WaitAllObject,
	WaitAnyObject


} OBJECT_WAIT_TYPE, * POBJECT_WAIT_TYPE;



typedef NTSTATUS(NTAPI* __LdrLoadDll)(
	_In_opt_ PWCHAR               PathToFile,
	_In_opt_ ULONG                Flags,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             ModuleHandle
	);
typedef NTSTATUS(NTAPI* __LdrUnloadDll)(
	IN HANDLE               ModuleHandle
	);
typedef VOID(NTAPI* __RtlInitAnsiString)(PANSI_STRING  	DestinationString,
	LPCSTR  	SourceString
	);
typedef VOID(NTAPI* __RtlInitUnicodeString)(
	PUNICODE_STRING         DestinationString,
	__drv_aliasesMem PCWSTR SourceString
	);

typedef NTSTATUS(NTAPI* __LdrGetProcedureAddress)(
	IN HMODULE              ModuleHandle,
	IN PANSI_STRING         FunctionName OPTIONAL,
	IN WORD                 Oridinal OPTIONAL,
	OUT PVOID* FunctionAddress
	);
typedef NTSTATUS(NTAPI* __LdrGetDllHandle)(
	IN PWORD                pwPath OPTIONAL,
	IN PVOID                Unused OPTIONAL,
	IN PUNICODE_STRING      ModuleFileName,
	OUT PHANDLE             pHModule
	);

typedef BOOL(WINAPI* __CryptAcquireContextW)(
	HCRYPTPROV* phProv,
	LPCWSTR    szContainer,
	LPCWSTR    szProvider,
	DWORD      dwProvType,
	DWORD      dwFlags
	);

typedef BOOL(WINAPI* __CryptReleaseContext)(
	HCRYPTPROV hProv,
	DWORD      dwFlags
	);
typedef NTSTATUS(NTAPI* __NtCreateMutant)(
	OUT PHANDLE             MutantHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN BOOLEAN              InitialOwner
	);
typedef BOOL(WINAPI* __CryptEncrypt)(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD      dwBufLen
	);

typedef NTSTATUS(NTAPI* __NtQueryInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* __NtSetInformationFile)(
	HANDLE                 FileHandle,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass
	);

typedef NTSTATUS(NTAPI* __RtlExpandEnvironmentStrings_U)(
	PCWSTR,
	const UNICODE_STRING*,
	UNICODE_STRING*,
	ULONG*
	);
typedef NTSTATUS (NTAPI *__NtWriteFile)(
	HANDLE           FileHandle,
	HANDLE           Event,
	PIO_APC_ROUTINE  ApcRoutine,
	PVOID            ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID            Buffer,
	ULONG            Length,
	PLARGE_INTEGER   ByteOffset,
	PULONG           Key
);

typedef ULONG(NTAPI* __RtlGetCurrentDirectory_U)(
	_In_ ULONG MaximumLength,
	_Out_bytecap_(MaximumLength) PWSTR Buffer
	);


typedef NTSTATUS(NTAPI* __NtOpenFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	ULONG              ShareAccess,
	ULONG              OpenOptions
	);

typedef NTSTATUS(NTAPI* __NtQueryDirectoryFile)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PIO_APC_ROUTINE        ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
	);

typedef NTSTATUS(NTAPI* __NtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

typedef BOOLEAN(NTAPI* __RtlDosPathNameToNtPathName_U)(
	IN PCWSTR DosName,
	OUT PUNICODE_STRING NtName,
	OUT PCWSTR* PartName,
	OUT PRTL_RELATIVE_NAME_U RelativeName
	);

typedef NTSTATUS(NTAPI* __NtCreateFile)(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
	);

typedef BOOL(WINAPI* __HeapFree)(
	HANDLE                 hHeap,
	DWORD                  dwFlags,
	_Frees_ptr_opt_ LPVOID lpMem
	);

typedef HANDLE(WINAPI* __GetProcessHeap)();

typedef NTSTATUS(NTAPI* __NtClose)(
	HANDLE Handle
	);

typedef NTSTATUS(NTAPI* __NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
	);

typedef NTSTATUS(NTAPI* __NtOpenProcess)(
	OUT PHANDLE             ProcessHandle,
	IN ACCESS_MASK          AccessMask,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN CLIENT_ID* ClientId
	);

typedef NTSTATUS(NTAPI* __NtTerminateProcess)(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus
);

typedef BOOL(WINAPI* __CryptStringToBinaryW)(
	LPCWSTR pszString,
	DWORD   cchString,
	DWORD   dwFlags,
	BYTE* pbBinary,
	DWORD* pcbBinary,
	DWORD* pdwSkip,
	DWORD* pdwFlags
	);

typedef BOOL(WINAPI* __CryptDecodeObjectEx)(
	DWORD              dwCertEncodingType,
	LPCSTR             lpszStructType,
	const BYTE* pbEncoded,
	DWORD              cbEncoded,
	DWORD              dwFlags,
	PCRYPT_DECODE_PARA pDecodePara,
	void* pvStructInfo,
	DWORD* pcbStructInfo
	);

typedef BOOL(WINAPI* __CryptDecodeObjectEx)(
	DWORD              dwCertEncodingType,
	LPCSTR             lpszStructType,
	const BYTE* pbEncoded,
	DWORD              cbEncoded,
	DWORD              dwFlags,
	PCRYPT_DECODE_PARA pDecodePara,
	void* pvStructInfo,
	DWORD* pcbStructInfo
	);

typedef BOOL(WINAPI* __CryptImportPublicKeyInfo)(
	HCRYPTPROV            hCryptProv,
	DWORD                 dwCertEncodingType,
	PCERT_PUBLIC_KEY_INFO pInfo,
	HCRYPTKEY* phKey
	);


typedef HLOCAL(WINAPI* __LocalFree)(
	_Frees_ptr_opt_ HLOCAL hMem
	);


typedef BOOL(WINAPI* __CryptEncrypt)(
	HCRYPTKEY  hKey,
	HCRYPTHASH hHash,
	BOOL       Final,
	DWORD      dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen,
	DWORD      dwBufLen
	);

typedef BOOL(WINAPI* __CryptExportKey)(
	HCRYPTKEY hKey,
	HCRYPTKEY hExpKey,
	DWORD     dwBlobType,
	DWORD     dwFlags,
	BYTE* pbData,
	DWORD* pdwDataLen
	);

typedef BOOL(WINAPI* __CryptGenKey)(
	HCRYPTPROV hProv,
	ALG_ID     Algid,
	DWORD      dwFlags,
	HCRYPTKEY* phKey
	);

typedef BOOL(WINAPI* __CryptDestroyKey)(
	HCRYPTKEY hKey
);
typedef NTSTATUS (NTAPI *__NtWaitForSingleObject)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
);

typedef LPVOID (WINAPI *__HeapAlloc)(
	HANDLE hHeap,
	DWORD  dwFlags,
	SIZE_T dwBytes
);

typedef NTSTATUS(NTAPI* __NtCreateKey)(
	OUT PHANDLE  	KeyHandle,
	IN ACCESS_MASK  	DesiredAccess,
	IN POBJECT_ATTRIBUTES  	ObjectAttributes,
	IN ULONG  	TitleIndex,
	IN PUNICODE_STRING Class  	OPTIONAL,
	IN ULONG  	CreateOptions,
	OUT PULONG Disposition  	OPTIONAL
);

typedef NTSTATUS (NTAPI *__NtSetValueKey)(
	HANDLE          KeyHandle,
	PUNICODE_STRING ValueName,
	ULONG           TitleIndex,
	ULONG           Type,
	PVOID           Data,
	ULONG           DataSize
);
typedef NTSTATUS (NTAPI *__NtReadFile)(
	_In_     HANDLE           FileHandle,
	_In_opt_ HANDLE           Event,
	_In_opt_ PIO_APC_ROUTINE  ApcRoutine,
	_In_opt_ PVOID            ApcContext,
	_Out_    PIO_STATUS_BLOCK IoStatusBlock,
	_Out_    PVOID            Buffer,
	_In_     ULONG            Length,
	_In_opt_ PLARGE_INTEGER   ByteOffset,
	_In_opt_ PULONG           Key
);

typedef NTSTATUS (NTAPI *__NtFlushBuffersFile)(
	HANDLE           FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock
);

typedef BOOLEAN (NTAPI *__RtlGenRandom)(
	PVOID RandomBuffer,
	ULONG RandomBufferLength
);

typedef  BOOL (WINAPI *__LookupPrivilegeValueW)(
	_In_opt_ LPCWSTR lpSystemName,
	_In_     LPCWSTR lpName,
	_Out_    PLUID   lpLuid
);
typedef BOOL (WINAPI *__ExitWindowsEx)(
	_In_ UINT uFlags,
	_In_ DWORD dwReason);

typedef DWORD (WINAPI *__GetLastError)();
typedef int (WINAPIV *__wsprintfW)(
	LPWSTR,
	LPCWSTR,
	...
);


typedef HBRUSH (WINAPI *__CreateSolidBrush)(
	COLORREF color
);
typedef ATOM (WINAPI *__RegisterClassExW)(
	const WNDCLASSEXW* Arg1
);
typedef BOOL (WINAPI *__GetWindowRect)(
	HWND   hWnd,
	LPRECT lpRect
);
typedef HWND (WINAPI *__GetDesktopWindow)();
typedef HWND (WINAPI *__CreateWindowExW)(
	DWORD     dwExStyle,
	LPCWSTR   lpClassName,
	LPCWSTR   lpWindowName,
	DWORD     dwStyle,
	int       X,
	int       Y,
	int       nWidth,
	int       nHeight,
	HWND      hWndParent,
	HMENU     hMenu,
	HINSTANCE hInstance,
	LPVOID    lpParam
);
typedef BOOL (WINAPI *__ShowWindow)(
	HWND hWnd,
	int  nCmdShow
);
typedef BOOL (WINAPI *__GetMessageW)(
	LPMSG lpMsg,
	HWND  hWnd,
	UINT  wMsgFilterMin,
	UINT  wMsgFilterMax
);
typedef BOOL (WINAPI *__TranslateMessage)(
	const MSG* lpMsg
);
typedef LRESULT (WINAPI *__DispatchMessageW)(
	const MSG* lpMsg
);
typedef BOOL (WINAPI *__DeleteObject)(
	HGDIOBJ ho
);
typedef void (WINAPI *__PostQuitMessage)(
	int nExitCode
);
typedef LRESULT (WINAPI* __DefWindowProcW)(
	HWND   hWnd,
	UINT   Msg,
	WPARAM wParam,
	LPARAM lParam
);
typedef COLORREF (WINAPI *__SetTextColor)(
	HDC      hdc,
	COLORREF color
);
typedef COLORREF (WINAPI *__SetBkColor)(
	HDC      hdc,
	COLORREF color
);
typedef LRESULT (WINAPI *__SendMessageW)(
	HWND   hWnd,
	UINT   Msg,
	WPARAM wParam,
	LPARAM lParam
);
typedef BOOL (WINAPI *__MoveWindow)(
	HWND hWnd,
	int  X,
	int  Y,
	int  nWidth,
	int  nHeight,
	BOOL bRepaint
);
typedef BOOL (WINAPI *__GetTextExtentPoint32W)(
	HDC     hdc,
	LPCWSTR lpString,
	int     c,
	LPSIZE  psizl
);
typedef HDC (WINAPI *__GetDC)(
	HWND hWnd
);
typedef HFONT (WINAPI *__CreateFontW)(
	int     cHeight,
	int     cWidth,
	int     cEscapement,
	int     cOrientation,
	int     cWeight,
	DWORD   bItalic,
	DWORD   bUnderline,
	DWORD   bStrikeOut,
	DWORD   iCharSet,
	DWORD   iOutPrecision,
	DWORD   iClipPrecision,
	DWORD   iQuality,
	DWORD   iPitchAndFamily,
	LPCWSTR pszFaceName
);









typedef BOOLEAN (NTAPI *__RtlCreateUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
);
typedef void (NTAPI *__RtlFreeUnicodeString)(
	PUNICODE_STRING UnicodeString
);
typedef NTSTATUS (NTAPI *__RtlOpenCurrentUser)(
	IN ACCESS_MASK DesiredAccess, 
	OUT PHANDLE KeyHandle
);


typedef NTSTATUS (NTAPI *__RtlCreateUserThread)(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PVOID          ClientID
);

typedef NTSTATUS (NTAPI *__NtDelayExecution)(
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval
);
typedef NTSTATUS (NTAPI *__NtOpenProcessToken)(
	IN HANDLE               ProcessHandle,
	IN ACCESS_MASK          DesiredAccess,
	OUT PHANDLE             TokenHandle
);
typedef NTSTATUS (NTAPI *__NtAdjustPrivilegesToken)(
	IN HANDLE               TokenHandle,
	IN BOOLEAN              DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES    TokenPrivileges,
	IN ULONG                PreviousPrivilegesLength,
	OUT PTOKEN_PRIVILEGES   PreviousPrivileges OPTIONAL,
	OUT PULONG              RequiredLength OPTIONAL
);

typedef NTSTATUS (NTAPI *__NtWaitForMultipleObjects)(



	IN ULONG                ObjectCount,
	IN PHANDLE              ObjectsArray,
	IN OBJECT_WAIT_TYPE     WaitType,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL
	);
typedef BOOLEAN (NTAPI *__RtlDosPathNameToRelativeNtPathName_U)(
	IN PCWSTR DosName,
	OUT PUNICODE_STRING NtName,
	OUT PCWSTR* PartName,
	OUT PRTL_RELATIVE_NAME_U RelativeName
);


typedef NTSTATUS (NTAPI *__RtlCreateUserThread)(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PVOID          ClientID
);

typedef NTSTATUS (NTAPI *__NtWaitForMultipleObjects)(
	IN ULONG                ObjectCount,
	IN PHANDLE              ObjectsArray,
	IN OBJECT_WAIT_TYPE     WaitType,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL
);


typedef struct _FILE_POSITION_INFORMATION {
	LARGE_INTEGER CurrentByteOffset;
} FILE_POSITION_INFORMATION, * PFILE_POSITION_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         NumberOfLinks;
	BOOLEAN       DeletePending;
	BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;




