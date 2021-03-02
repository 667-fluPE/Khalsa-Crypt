#include "khalsa_g.h"
#include "khalsa_clib.h"
#define KHALSA_MAX_DRIVE_LENGTH 4096
#define MAX_DRIVE_LENGTH 26+1

BOOL OnFindDrive_Encrypt(LPWSTR lpszDriveName, LPVOID lpParam);

BOOL ScanDrives(BOOL(*pfOnFindDrive)(LPWSTR, LPVOID), LPVOID lpParam);