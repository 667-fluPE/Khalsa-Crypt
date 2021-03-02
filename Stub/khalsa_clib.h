#include <Windows.h>

int __CmpStrW(LPCWSTR s1, LPCWSTR s2);

int __CmpStrA(LPCSTR s1, LPCSTR s2);
SIZE_T _strlen(LPCSTR lpszStr);
SIZE_T _wcslen(LPCWSTR lpszStr);
void* _memcpy(void* dest, const void* src, size_t count);

int __cdecl _memcmp(const void* s1, const void* s2, size_t n);
PCHAR DecryptString(LPCSTR lpszSourceStr, LPSTR lpszKey);

PVOID ZeroBuffer(_Out_writes_bytes_all_(Size) PVOID Pointer, _In_ SIZE_T Size);
UCHAR lpStrApiName[73];
UCHAR lpDecryptStr[73];