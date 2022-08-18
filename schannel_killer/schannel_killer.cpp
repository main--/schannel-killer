// schannel_killer.cpp : Definiert die exportierten Funktionen für die DLL-Anwendung.
//

#include "stdafx.h"
#include "schannel_killer.h"

#define SECURITY_WIN32
#include "Security.h"

#include <cstdio>
#include <cstdlib>

static SecurityFunctionTableW TableW;
static SecurityFunctionTableA TableA;
static PSecurityFunctionTableW OriginalW;
static PSecurityFunctionTableA OriginalA;

static FILE* TextLog;
static FILE* BinaryLog;
static HANDLE LogMutex;

static SECURITY_STATUS SEC_ENTRY InitializeSecurityContextHookW(PCredHandle phCredential, PCtxtHandle phContext, WCHAR* pszTargetName, ULONG fContextReq, ULONG Reserved1, ULONG TargetDataRep, PSecBufferDesc pInput, ULONG Reserved2, PCtxtHandle phNewContext, PSecBufferDesc pOutput, PULONG pfContextAttr, PTimeStamp ptsExpiry)
{
	if (pInput)
	{
		for (unsigned int i = 0; i < pInput->cBuffers; i++)
		{
			if (pInput->pBuffers[i].BufferType == SECBUFFER_PKG_PARAMS)
			{
				TerminateProcess(GetCurrentProcess(), 42);
			}
		}
	}


	WaitForSingleObject(LogMutex, INFINITE);
	fprintf(TextLog, "Connecting to '%ls' (%p)\n", pszTargetName, phContext);
	if (pszTargetName != nullptr)
	{
		fputc('N', BinaryLog);
		fwrite(&phNewContext, sizeof(phContext), 1, BinaryLog);
		
		int len = WideCharToMultiByte(CP_UTF8, 0, pszTargetName, -1, nullptr, 0, nullptr, nullptr);
		char* buf = (char*)malloc(len);
		len = WideCharToMultiByte(CP_UTF8, 0, pszTargetName, -1, buf, len, nullptr, nullptr);
		fwrite(buf, len, 1, BinaryLog);
	}
	ReleaseMutex(LogMutex);

	return OriginalW->InitializeSecurityContextW(phCredential, phContext, pszTargetName, fContextReq, Reserved1, TargetDataRep, pInput, Reserved2, phNewContext, pOutput, pfContextAttr, ptsExpiry);
}

static void DumpBuffers(PCtxtHandle phContext, PSecBufferDesc pMessage, bool out)
{
	WaitForSingleObject(LogMutex, INFINITE);
	for (unsigned int i = 0; i < pMessage->cBuffers; i++)
	{
		PSecBuffer buf = &pMessage->pBuffers[i];
		if (buf->BufferType != 1)
			continue;

		fputc('B', BinaryLog);
		fputc(out, BinaryLog);
		fwrite(&phContext, sizeof(phContext), 1, BinaryLog);
		DWORD len = buf->cbBuffer;
		fwrite(&len, 4, 1, BinaryLog);
		fwrite(buf->pvBuffer, buf->cbBuffer, 1, BinaryLog);
		fflush(BinaryLog);

		char* whothis = (char*)malloc(buf->cbBuffer + 1);
		whothis[buf->cbBuffer] = '\0';
		memcpy(whothis, buf->pvBuffer, buf->cbBuffer);
		fprintf(TextLog, "[%p:%s] %s (", phContext, out ? "OUT" : "IN", whothis);
		free(whothis);

		for (unsigned int j = 0; j < buf->cbBuffer; j++)
		{
			fprintf(TextLog, "%02x ", ((BYTE*)buf->pvBuffer)[j]);
		}
		fputs(")\n", TextLog);
	}
	ReleaseMutex(LogMutex);
}

static SECURITY_STATUS SEC_ENTRY DecryptMessageHook(PCtxtHandle phContext, PSecBufferDesc pMessage, ULONG MessageSeqNo, PULONG pfQOP)
{
	int ret = OriginalW->DecryptMessage(phContext, pMessage, MessageSeqNo, pfQOP);
	DumpBuffers(phContext, pMessage, false);
	return ret;
}

static SECURITY_STATUS SEC_ENTRY EncryptMessageHook(PCtxtHandle phContext, ULONG fQOP, PSecBufferDesc pMessage, ULONG MessageSeqNo)
{
	DumpBuffers(phContext, pMessage, true);
	return OriginalW->EncryptMessage(phContext, fQOP, pMessage, MessageSeqNo);
}

static void InitForwarding()
{
	LogMutex = CreateMutex(nullptr, false, nullptr);

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

	HMODULE mod = LoadLibrary(TEXT("C:\\Windows\\System32\\Secur32.dll"));

	OriginalW = ((INIT_SECURITY_INTERFACE_W)GetProcAddress(mod, "InitSecurityInterfaceW"))();
	OriginalA = ((INIT_SECURITY_INTERFACE_A)GetProcAddress(mod, "InitSecurityInterfaceA"))();

	memcpy(&TableW, OriginalW, sizeof(TableW));
	memcpy(&TableA, OriginalA, sizeof(TableA));

	// here go the hooks
	TableA.EncryptMessage = TableW.EncryptMessage = EncryptMessageHook;
	TableA.DecryptMessage = TableW.DecryptMessage = DecryptMessageHook;
	TableW.InitializeSecurityContextW = InitializeSecurityContextHookW;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InitForwarding();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

#pragma comment(linker, "/EXPORT:InitSecurityInterfaceW=InitSecurityInterfaceW_hook")
extern "C" PSecurityFunctionTableW SEC_ENTRY InitSecurityInterfaceW_hook(void)
{
    return &TableW;
}

#pragma comment(linker, "/EXPORT:InitSecurityInterfaceA=InitSecurityInterfaceA_hook")
extern "C" PSecurityFunctionTableA SEC_ENTRY InitSecurityInterfaceA_hook(void)
{
	return &TableA;
}
