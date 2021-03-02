#pragma once
#include "khalsa_g.h"
BOOL Khalsa_RegisterStartup(LPWSTR szCurrentPath);
ULONG Khalsa_AddToRegistry(IN LPCWSTR pwszKeyName, IN LPCWSTR pwszValueName, IN ULONG ulType, OUT PVOID pvData, IN ULONG cbDataSize, IN BOOL bSetValue);
