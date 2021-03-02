#include "khalsa_peldr.h"
PVOID My_GetModuleBase(LPCWSTR lpszModule) {
	PVOID Current_peb = NtCurrentTeb()->ProcessEnvironmentBlock;
	PPEB peb = (PPEB)Current_peb;
	PLIST_ENTRY tail = &peb->Ldr->InMemoryOrderModuleList;
	PLIST_ENTRY list = tail->Flink;
	do {
		PLDR_DATA_TABLE_ENTRY module = (PLDR_DATA_TABLE_ENTRY)list;

		if (!__CmpStrW(module->FullDllName.Buffer, lpszModule)) {
			PVOID BaseAddr = module->Reserved2[0];

			return BaseAddr;
		}
		list = list->Flink;
	} while (list != tail);
	return NULL;
}

PVOID My_GetModuleProcedureAddress(PVOID pModule, LPCSTR RoutineName) {
	PIMAGE_DOS_HEADER ImgDosHdrs = (PIMAGE_DOS_HEADER)pModule;
	if (ImgDosHdrs->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	PIMAGE_NT_HEADERS32 ImgNtHdrs32 = (PIMAGE_NT_HEADERS32)((PCHAR)pModule + ImgDosHdrs->e_lfanew);
	if (ImgNtHdrs32->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	if (ImgNtHdrs32->FileHeader.SizeOfOptionalHeader < 96 || ImgNtHdrs32->OptionalHeader.NumberOfRvaAndSizes == 0)
		return NULL;

	DWORD ExportTable = ImgNtHdrs32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (!ExportTable)
		return NULL;

	PEXPORT_DIRECTORY_TABLE pExportTable = (PEXPORT_DIRECTORY_TABLE)((PCHAR)pModule + ExportTable);
	PVOID OrdinalTable = (PBYTE)pModule + pExportTable->OrdinalTableRVA;
	PVOID NamePointerTable = (PBYTE)pModule + pExportTable->NamePointerTableRVA;
	PVOID ExportAddressTable = (PBYTE)pModule + pExportTable->ExportAddressTableRVA;

	for (DWORD i = 0; i < pExportTable->NamePointerTableSize; i++) {
		DWORD NameRVA = ((PDWORD)NamePointerTable)[i];
		const PCHAR NameAddr = (PCHAR)pModule + NameRVA;

		if (__CmpStrA(NameAddr, RoutineName) != 0)
			continue;

		WORD od = ((PWORD)OrdinalTable)[i] + (WORD)pExportTable->OrdinalBase;
		WORD RealOrdinal = od - (WORD)pExportTable->OrdinalBase;
		DWORD ExportAddr = 0;
		ExportAddr = ((PDWORD)ExportAddressTable)[RealOrdinal];
		PVOID RoutineAddr = (PCHAR)pModule + ExportAddr;
		return RoutineAddr;
	}
	return NULL;
}
