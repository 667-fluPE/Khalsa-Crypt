#include "khalsa_resolve.h"
#include "apis.h"
#include "khalsa_clib.h"
extern PVOID My_GetModuleBase(LPCWSTR lpszModule);
extern PVOID My_GetModuleProcedureAddress(PVOID pModule, LPCSTR RoutineName);
BOOL ResolveInitalNtImports() {
	BOOL rv = FALSE;
    
	PVOID ntdll = My_GetModuleBase(NTDLL);
	if (!ntdll) {
		return rv;
	}
	

    

    PCHAR pApiName  = DecryptString(LDRLOADDLL, KEY);
	_LdrLoadDll = (__LdrLoadDll)My_GetModuleProcedureAddress(ntdll, pApiName);
    
    pApiName = DecryptString(RTLINITANSISTRING, KEY);
	_RtlInitAnsiString = (__RtlInitAnsiString)My_GetModuleProcedureAddress(ntdll, pApiName);
    
    pApiName = DecryptString(RLTINITUNICODESTRING, KEY); 
	_RtlInitUnicodeString = (__RtlInitUnicodeString)My_GetModuleProcedureAddress(ntdll, pApiName);
    
    pApiName = DecryptString(LDRGETPROCEDUREADDRESS, KEY);
	_LdrGetProcedureAddress = (__LdrGetProcedureAddress)My_GetModuleProcedureAddress(ntdll, pApiName);
    
    pApiName = DecryptString(LDRGETDLLHANDLE, KEY);
	_LdrGetDllHandle = (__LdrGetDllHandle)My_GetModuleProcedureAddress(ntdll, pApiName);
	if (
		(_LdrLoadDll != NULL) && (_RtlInitAnsiString != NULL) &&
		(_RtlInitUnicodeString != NULL) && (_LdrGetProcedureAddress != NULL) &&
		(_LdrGetDllHandle != NULL)
	) {
			rv = TRUE;
	}
	return rv;
}
BOOL ResolveDLLs() {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOL rv = TRUE;

	SIZE_T Counter = 0;
	while (EncryptedStringDll[Counter].Dll != NULL) {
		ULONG uLen = 0;
		LPCWSTR DllName = EncryptedStringDll[Counter].Dll;
		UNICODE_STRING psDllName = { 0 };
		_RtlInitUnicodeString(&psDllName, DllName);
		status = _LdrLoadDll(NULL, 0, &psDllName, EncryptedStringDll[Counter].hDll);
		if (!NT_SUCCESS(status)) {
			rv = FALSE;
			break;
		}
		status = _LdrGetDllHandle(NULL, NULL, &psDllName, &EncryptedStringDll[Counter].hDll);
		if (!NT_SUCCESS(status)) {
			rv = FALSE;
			break;
		}
		Counter++;
	}
	return rv;
}

BOOL ResolveAPIs() {

	SIZE_T Counter = 0;
	BOOL rv = TRUE;

	while (EncryptedStringApi[Counter].STRING != NULL) {
		ULONG uLen = 0;
        LPCSTR Decrypted_API = DecryptString(EncryptedStringApi[Counter].STRING, KEY);
		NTSTATUS status = STATUS_UNSUCCESSFUL;

		ANSI_STRING ANSIS_MyString = { 0 };
		_RtlInitAnsiString(&ANSIS_MyString, Decrypted_API);
		
		if (EncryptedStringDll[EncryptedStringApi[Counter].Type].hDll == NULL) {
			rv = FALSE;
			break;
		}
		status = _LdrGetProcedureAddress(EncryptedStringDll[EncryptedStringApi[Counter].Type].hDll, &ANSIS_MyString, 0, (PVOID*)EncryptedStringApi[Counter].lpFunc);
		rv = NT_SUCCESS(status);
        
		Counter++;
	}
	return rv;

}
BOOL ResolveImports() {
	BOOL rv = ResolveInitalNtImports();
	if (!rv) {
		return rv;
	}
	rv = ResolveDLLs();
	if (!rv) {
		return rv;
	}
	rv = ResolveAPIs();
	return rv;
}


