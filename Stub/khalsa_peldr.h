#ifndef PELDR
#define PELDR
#pragma warning(disable:4201)
#include <Windows.h>
#include <winternl.h>
#include <winnt.h>
#include "khalsa_clib.h"
typedef struct _EXPORT_DIRECTORY_TABLE {
	DWORD ExportFlags;
	DWORD TimeStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD NameRVA;
	DWORD OrdinalBase;
	DWORD ExportAddressTableSize;
	DWORD NamePointerTableSize;
	DWORD ExportAddressTableRVA;
	DWORD NamePointerTableRVA;
	DWORD OrdinalTableRVA;
} EXPORT_DIRECTORY_TABLE, * PEXPORT_DIRECTORY_TABLE;
#endif