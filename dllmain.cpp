#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#pragma comment(lib, "Psapi.lib")
#include "resource.h"
#include "patternscan.hpp"
#include "MinHook/minhook.hpp"
HMODULE g_self = 0;
void __fastcall HookVpnBypass(DWORD*, void*, char) {}
bool __cdecl HookIsNetworkConnected(DWORD*, DWORD*) { return false; }
bool __fastcall HookIsNotViolationCode(void*, void*, unsigned int) { return true; }
int __fastcall HookExecuteSecurityViolationKick(void*, void*) { return 0; }
int __fastcall HookSendClientKick(void*, void*, char) { return 1; }
int __cdecl HookSendLogger(int, void*, int, int, void*) { return 0; }
int __fastcall HookSetClientKick(void*, void*, void*, void*, char, int) { return 0; }
void __fastcall HookVfB00Z00Scanner(void*, void*, int) {}
int __fastcall HookSetClientKickNew(void*, void*, char) { return 0; }
int __fastcall HookScanModuleIntegrity(void*, void*, DWORD*) { return 0; }
PVOID oVpnBypass = nullptr;
PVOID oIsNetworkConnected = nullptr;
PVOID oIsNotViolationCode = nullptr;
PVOID oExecuteSecurityViolationKick = nullptr;
PVOID oSendClientKick = nullptr;
PVOID oSendLogger = nullptr;
PVOID oSetClientKick = nullptr;
PVOID oVfB00Z00Scanner = nullptr;
PVOID oSetClientKickNew = nullptr;
PVOID oScanModuleIntegrity = nullptr;
decltype(&ShellExecuteA) o_shellexecutea = nullptr;
HINSTANCE
WINAPI
hooked_shellexecutea(
	_In_ HWND hwnd,
	_In_ LPCSTR operation,
	_In_ LPCSTR file,
	_In_ LPCSTR parameters,
	_In_ LPCSTR directory,
	_In_ INT showcmd)
{
	if (file && strstr(file, "vk.com/project414"))
		file = "https://discord.com/users/1138590550635839488";
	return o_shellexecutea(hwnd, operation, file, parameters, directory, showcmd);
}
void CreateNetcHooks()
{
	printf("creating hooks\n");
	MH_Initialize();
	DWORD t = 0;
	t = Utils::PatternScan("netc.dll", "55 8B EC 53 56 57 8B F1 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 E8", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookVpnBypass, reinterpret_cast<LPVOID*>(&oVpnBypass)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 8B 45 0C 8B D0 83 78 14 0F 76 02 8B 10 8B 4D 08 56 8B F1 83 79 14 0F 76 02 8B 31 FF 70 10 52 FF 71 10 56 E8 ? ? ? ? 83 C4 10 34", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookIsNetworkConnected, reinterpret_cast<LPVOID*>(&oIsNetworkConnected)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 8B 45 08 33 D2 56", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookIsNotViolationCode, reinterpret_cast<LPVOID*>(&oIsNotViolationCode)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 64 A1 ? ? ? ? 33 C5 89 45 F0 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B F1 50 B8 FE 14 71 4B B8 DE 2C EB 61 B8 8E 82 D9 85 B8 C2 CC B3 92 B8 3E A4 D9", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookExecuteSecurityViolationKick, reinterpret_cast<LPVOID*>(&oExecuteSecurityViolationKick)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 F0 56 57 50 8D 45 F4 64 A3 ? ? ? ? 8B F9 89 7D 84 50", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookSendClientKick, reinterpret_cast<LPVOID*>(&oSendClientKick)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 51 56 A1 ? ? ? ? 33 C5 50 8D 45 ? 64 A3 ? ? ? ? A1 ? ? ? ? 85 C0 75 ? 68 ? ? ? ? E8 ? ? ? ? 8B F0 33 C0 68 ? ? ? ? 83 FE ? 8B CE 6A ? 0F 44 C8 51 E8 ? ? ? ? 83 C4 ? 89 75 ? C7 45 ? ? ? ? ? 85 F6 74 ? 8B CE E8 ? ? ? ? EB ? 33 C0 C7 45 ? ? ? ? ? A3 ? ? ? ? FF 75 ? 8B C8 FF 75 ? FF 75 ? FF 75 ? FF 75 ? E8 ? ? ? ? FF 05", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookSendLogger, reinterpret_cast<LPVOID*>(&oSendLogger)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "55 8B EC 6A FF 68 ? ? ? ? 64 A1 00 00 00 00 50 83 EC 34 A1 ? ? ? ? 33 C5 89 45 F0 56 57 50 8D 45 F4 64 A3 00 00 00 00 8B F1 50 B8 1E 22 84 8E B8 22 59 21 B2 B8 FE", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookSetClientKick, reinterpret_cast<LPVOID*>(&oSetClientKick)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 BD ? ? ? ? 50 B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? B8 ? ? ? ? 58 83 7B", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookVfB00Z00Scanner, reinterpret_cast<LPVOID*>(&oVfB00Z00Scanner)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "53 8B DC 83 EC ? 83 E4 ? 83 C4 ? 55 8B 6B ? 89 6C 24 ? 8B EC 6A ? 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 B8 ? ? ? ? E8 ? ? ? ? A1 ? ? ? ? 33 C5 89 45 ? 56 57 50 8D 45 ? 64 A3 ? ? ? ? 8B F9 89 BD ? ? ? ? C7 85", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookSetClientKickNew, reinterpret_cast<LPVOID*>(&oSetClientKickNew)); MH_EnableHook((LPVOID)t); }
	t = Utils::PatternScan("netc.dll", "53 8B DC 83 EC 08 83 E4 F0 83 C4 04 55 8B 6B 04 89 6C 24 04 8B EC 6A FF 68 ? ? ? ? 64 A1 ? ? ? ? 50 53 81 EC ? ? ? ? A1 ? ? ? ? 33 C5 89 45 EC 56 57 50 8D 45 F4 64 A3 ? ? ? ? 89 8D ? ? ? ? 8B 7B 08 33 C0", false);
	if (t) { MH_CreateHook((LPVOID)t, &HookScanModuleIntegrity, reinterpret_cast<LPVOID*>(&oScanModuleIntegrity)); MH_EnableHook((LPVOID)t); }
	MH_CreateHook(&ShellExecuteA, &hooked_shellexecutea, reinterpret_cast<LPVOID*>(&o_shellexecutea));
	MH_EnableHook(&ShellExecuteA);
	printf("hooks created\n");
}
void main()
{
	printf("prova\n");
	HRSRC hres = FindResourceA(g_self, MAKEINTRESOURCEA(IDR_GAMESNUS), RT_RCDATA);
	DWORD ressize = SizeofResource(g_self, hres);
	HGLOBAL hglob = LoadResource(g_self, hres);
	BYTE* resptr = (BYTE*)LockResource(hglob);
	char tmppath[MAX_PATH];
	char tmpfile[MAX_PATH];
	GetTempPathA(MAX_PATH, tmppath);
	DWORD rnd = GetTickCount() ^ GetCurrentProcessId() ^ GetCurrentThreadId();
	wsprintfA(tmpfile, "%ssn%x%x.dll", tmppath, rnd, GetTickCount());
	HANDLE hf = CreateFileA(tmpfile, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD written = 0;
	WriteFile(hf, resptr, ressize, &written, 0);
	CloseHandle(hf);
	while (!GetModuleHandleA("netc.dll"))
	{
		Sleep(100);
	}
	CreateNetcHooks();
	printf("waiting entrypoint...\n");
	LoadLibraryA(tmpfile);
	printf("entrypoint called\n");
}
bool __stdcall DllMain(HANDLE hinstDLL, uint32_t fdwReason, void* lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		g_self = (HMODULE)hinstDLL;
		AllocConsole();
		SetConsoleTitleA("prova");
		freopen("CONOUT$", "w", stdout);
		CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(main), 0, 0, 0);
	}
	return true;
}
