// victim.cpp : Definiert den Einstiegspunkt für die Konsolenanwendung.
//

#include "stdafx.h"
#define SECURITY_WIN32
#include "Security.h"

#include <cstdlib>

int main()
{
	FILE* TextLog, *BinaryLog;

	size_t preflen;
	char prefbuf[512];
	getenv_s(&preflen, prefbuf, 256, "USERPROFILE");
	if (preflen != 0)
	{
		preflen -= 1;
		memcpy(&prefbuf[preflen], "\\schannel.log", 14);
		fopen_s(&TextLog, prefbuf, "w");
		memcpy(&prefbuf[preflen], "\\schannel.bin", 14);
		fopen_s(&BinaryLog, prefbuf, "wb");
	}



	char buf[256] = "uiaeuiaeuiaeuiaeuiaeuiaeuiae";
	int len = WideCharToMultiByte(CP_UTF8, 0, L"fuckyou", -1, buf, sizeof(buf), nullptr, nullptr);


	HMODULE mod = LoadLibraryA("Secur32.dll");
	FARPROC proc = GetProcAddress(mod, "InitSecurityInterfaceW");
	PSecurityFunctionTable table = ((PSecurityFunctionTable(SEC_ENTRY *)(void))proc)();
	int ret = table->EncryptMessage(nullptr, 42, nullptr, 1337);
    return 0;
}

