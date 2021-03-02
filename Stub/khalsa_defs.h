#include <Windows.h>

#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) ((_ucStr)->Buffer = (_buf), (_ucStr)->Length = 0, (_ucStr)->MaximumLength = (USHORT)(_bufSize))
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
#define NTSTRSAFE_MAX_CCH   2147483647
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define FileFullDirectoryInformation 2
#define FileBothDirectoryInformation 3
#define FileStandardInformation 5
#define FileRenameInformation 10
#define FilePositionInformation 14

#define REG_FAILED 0x00000000L

#define ProcessDeviceMap 23
#define FILE_ATTRIBUTE_VALID_FLAGS 0x00003fb7
#define MAX_DOS_DRIVES 26
#define STATUS_BUFFER_TOO_SMALL 0xC0000023
#define STATUS_NO_MORE_FILES 0x80000006
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000
#define STATUS_UNSUCCESSFUL 0xC0000001
#define STATUS_END_OF_FILE 0xC0000011
#define STATUS_OBJECT_NAME_COLLISION 0xC0000035
#define STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_OBJECT_NAME_NOT_FOUND 0xC0000034
#define STATUS_OBJECT_TYPE_MISMATCH 0xC0000024
#define STATUS_OBJECT_PATH_NOT_FOUND 0xC000003A
#define STATUS_ACCESS_DENIED 0xC0000022