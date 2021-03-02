#include "khalsa_clib.h"
#include <stdio.h>
PVOID ZeroBuffer(_Out_writes_bytes_all_(Size) PVOID Pointer, _In_ SIZE_T Size){
    volatile PCHAR vptr = (volatile PCHAR)Pointer;
    if (vptr == NULL)
        return NULL;

    PCHAR endptr = (PCHAR)vptr + Size;
    while (vptr < endptr) {
        *vptr = 0; vptr++;
    }
    return Pointer;
 }
int __CmpStrA(LPCSTR s1, LPCSTR s2)
{
    while (*s1 == *s2++)
    {
        if (*s1++ == 0)
            return 0;
    }

    return (*(PDWORD)s1 - *(PDWORD) --s2);
}

int __CmpStrW(LPCWSTR s1, LPCWSTR s2)
{
    while (*s1 == *s2++)
    {
        if (*s1++ == 0)
            return 0;
    }

    return (*(PDWORD)s1 - *(PDWORD) --s2);
}

SIZE_T _wcslen(LPCWSTR lpszStr)
{
    size_t len = 0;
    for (LPWSTR buf = (LPWSTR)lpszStr; *buf != 0; buf++, len++);
    return len;
}


SIZE_T _strlen(LPCSTR lpszStr)
{
    size_t len = 0;
    for (char* buf = (char*)lpszStr; *buf != 0; buf++, len++);
    return len;
}

void* _memcpy(void* dest, const void* src, size_t count) {
    char* dst8 = (char*)dest;
    char* src8 = (char*)src;

    while (count--) {
        *dst8++ = *src8++;
    }
    return dest;
}

int __cdecl _memcmp(const void* s1, const void* s2, size_t n)
{
    if (n != 0) {
        const unsigned char* p1 = s1, * p2 = s2;
        do {
            if (*p1++ != *p2++)
                return (*--p1 - *--p2);
        } while (--n != 0);
    }
    return 0;
}

char* _strchr(register const char* s, int c)
{
    do {
        if (*s == c)
        {
            return (char*)s;
        }
    } while (*s++);
    return (0);
}

int _isalpha(int c)
{
    return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'));
}
int _isdigit(int c)
{
    return (c >= '0' && c <= '9');
}


int _isalnum(int c)
{
    return (_isalpha(c) || _isdigit(c));
}



BOOL is_base64(wchar_t c) {
    return (_isalnum(c) || (c == '+') || (c == '/'));
}



PUCHAR rc4(unsigned char * ByteInput, DWORD dwByte, unsigned char * pwd) //changed to address
{
    DWORD i, j = 0, t, tmp, tmp2, s[256], k[256], ByteLen = dwByte;
    for (tmp = 0; tmp < 256; tmp++) {
        s[tmp] = tmp;
        k[tmp] = pwd[(tmp % strlen((char * ) pwd))];
    }
    for (i = 0; i < 256; i++) {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
    i = j = 0;


    for (tmp = 0; tmp < dwByte; tmp++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp2 = s[i];
        s[i] = s[j];
        s[j] = tmp2;
        t = (s[i] + s[j]) % 256;
        if (s[t] == ByteInput[tmp])
            lpStrApiName[tmp] = ByteInput[tmp];
        else
            lpStrApiName[tmp] = s[t] ^ ByteInput[tmp];
    }
    lpStrApiName[tmp] = '\0';
    return lpStrApiName;
}
unsigned char* hex2bin(const char* str)
{
    int len, h;
    unsigned char * p, c;


    if (!str)
        return NULL;

    len = 0;
    p = (unsigned char*)str;
    while (*p++)
        len++;

    h = !(len % 2) * 4;
    p = lpDecryptStr;
    *p = 0;

    c = *str;
    while (c)
    {
        if (('0' <= c) && (c <= '9'))
            *p += (c - '0') << h;
        else if (('A' <= c) && (c <= 'F'))
            *p += (c - 'A' + 10) << h;
        else if (('a' <= c) && (c <= 'f'))
            *p += (c - 'a' + 10) << h;
        else
            return NULL;

        str++;
        c = *str;

        if (h)
            h = 0;
        else
        {
            h = 4;
            p++;
            *p = 0;
        }
    }

    return lpDecryptStr;
}


PCHAR DecryptString(LPCSTR lpszSourceStr, LPSTR lpszKey) {
    DWORD dwSource = strlen(lpszSourceStr);
    ZeroBuffer(lpDecryptStr, sizeof(lpDecryptStr));
    ZeroBuffer(lpStrApiName, sizeof(lpStrApiName));
    unsigned int output_size = dwSource / 2;
    PUCHAR buf = hex2bin(lpszSourceStr);
    PUCHAR dec = rc4(buf, output_size, lpszKey);
    return dec;
}
