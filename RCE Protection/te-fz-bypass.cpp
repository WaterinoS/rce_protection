#include "te-fz-bypass.h"
#include "te-rce-protection.h"

#include <d3d9.h>
#include <vector>
#include <string>
#include <regex>
#include <fstream>

#include "Detours/detours_x86.h"
#pragma comment(lib, "Detours/detours_x86.lib")

namespace te::rce::fz::bypass
{
	// ---------- Core Structures ----------
	struct ManualMapResult {
		void* imageBase = nullptr;
		void* entryPoint = nullptr;
		size_t imageSize = 0;
	};

	// ---------- Signatures ----------
	constexpr const char* SIG_FENIXZONE_CHAT_PUSH = "55 0F BA FD 27 F5 89 E5 57 F9 66 F7 C6 ? ? 3B D6 56 8D B5 ? ? ? ? E9 ? ? ? ?";
	constexpr const char* SIG_SERVER_COMMUNICATION = "FF 74 24 10 9D 8D 64 24 1C E8 ? ? ? ? 0F 84";
	constexpr const char* SIG_MESSAGE_NUMBER = "C7 05 ? ? ? ? ? ? ? ? E8 ? ? ? ? C7 44 24";

	// ---------- Function Pointers ----------
	using SendCommandFunc = int(__cdecl*)(const char*);
	using ChatPushFunc = int(__stdcall*)(int);
	using ServerCommFunc = void(__cdecl*)(void);
	using WriteFileFunc = BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
	using ExitProcessFunc = VOID(WINAPI*)(UINT);
	using TerminateProcessFunc = BOOL(WINAPI*)(HANDLE, UINT);

	// ---------- Global Variables ----------
	static SendCommandFunc g_SendCommand = nullptr;
	static ChatPushFunc g_ChatPush_Orig = nullptr;
	static ServerCommFunc g_ServerComm_Orig = nullptr;
	static WriteFileFunc g_WriteFile_Orig = nullptr;
	static ExitProcessFunc g_ExitProcess_Orig = nullptr;
	static TerminateProcessFunc g_TerminateProcess_Orig = nullptr;

	static std::recursive_mutex g_memoryProtectionMutex;

	// ---------- Pattern Scanning ----------
	static std::vector<int> SigToBytes(const char* s)
	{
		std::vector<int> out;
		out.reserve(64);
		for (; *s; )
		{
			if (*s == ' ') { ++s; continue; }
			if (*s == '?') {
				out.push_back(-1);
				if (*(s + 1) == '?') ++s;
				++s;
				continue;
			}
			if (isxdigit((unsigned char)s[0]) && isxdigit((unsigned char)s[1]))
			{
				char b[3] = { s[0], s[1], 0 };
				out.push_back(strtoul(b, nullptr, 16));
				s += 2;
			}
			else { ++s; }
		}
		return out;
	}

	static uintptr_t FindInSection(uint8_t* start, size_t len, const char* sig)
	{
		auto pat = SigToBytes(sig);
		const size_t n = pat.size();
		if (!n || len < n) return 0;

		for (size_t i = 0; i <= len - n; ++i)
		{
			bool ok = true;
			for (size_t j = 0; j < n; ++j)
			{
				if (pat[j] != -1 && start[i + j] != (uint8_t)pat[j]) {
					ok = false;
					break;
				}
			}
			if (ok) return (uintptr_t)(start + i);
		}
		return 0;
	}

	static uintptr_t PatternScanModule(HMODULE hMod, const char* sig)
	{
		if (!hMod) return 0;
		auto* dos = (IMAGE_DOS_HEADER*)hMod;
		auto* nt = (IMAGE_NT_HEADERS*)((uint8_t*)hMod + dos->e_lfanew);
		auto* sec = IMAGE_FIRST_SECTION(nt);

		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
		{
			if (memcmp(sec->Name, ".text", 5) && memcmp(sec->Name, ".60C", 4)) continue;
			uint8_t* base = (uint8_t*)hMod + sec->VirtualAddress;
			uintptr_t hit = FindInSection(base, sec->Misc.VirtualSize, sig);
			if (hit) return hit;
		}
		return 0;
	}

	// ---------- File I/O ----------
	static bool ReadFileToVector(const std::string& path, std::vector<uint8_t>& out, const char* tag)
	{
		out.clear();
		std::ifstream f(path, std::ios::binary | std::ios::ate);
		if (!f) {
			te::sdk::helper::logging::Log("[%s] Failed to open: %s", tag, path.c_str());
			return false;
		}

		std::streamsize sz = f.tellg();
		if (sz <= 0) {
			te::sdk::helper::logging::Log("[%s] Empty file: %s", tag, path.c_str());
			return false;
		}

		out.resize(static_cast<size_t>(sz));
		f.seekg(0, std::ios::beg);
		if (!f.read(reinterpret_cast<char*>(out.data()), sz)) {
			te::sdk::helper::logging::Log("[%s] Read failed: %s", tag, path.c_str());
			out.clear();
			return false;
		}

		te::sdk::helper::logging::Log("[%s] Loaded %zu bytes from %s", tag, out.size(), path.c_str());
		return true;
	}

	// ---------- Safe Memory Operations ----------
	bool SafeVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		std::lock_guard<std::recursive_mutex> lock(g_memoryProtectionMutex);
		return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) != FALSE;
	}

	BOOL SafeReadMemory(void* address, void* buffer, size_t size)
	{
		__try {
			memcpy(buffer, address, size);
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	BOOL SafeExtractString(int address, char* buffer, size_t bufferSize, size_t* actualLength)
	{
		*actualLength = 0;
		if (address == 0 || bufferSize == 0) return FALSE;

		__try {
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery((void*)address, &mbi, sizeof(mbi)) ||
				mbi.State != MEM_COMMIT ||
				!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
				return FALSE;
			}

			char* str = reinterpret_cast<char*>(address);
			size_t len = strnlen(str, bufferSize - 1);

			if (len > 0 && len < bufferSize) {
				memcpy(buffer, str, len);
				buffer[len] = '\0';
				*actualLength = len;
				return TRUE;
			}
			return FALSE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	BOOL SafeCallDllMain(void* entryPoint, void* base)
	{
		if (!entryPoint || !base) return FALSE;
		typedef BOOL(WINAPI* DllMainT)(HINSTANCE, DWORD, LPVOID);
		DllMainT DllMainFn = reinterpret_cast<DllMainT>(entryPoint);

		BOOL ok = FALSE;
		__try {
			ok = DllMainFn(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			te::sdk::helper::logging::Log("[DllMain] Exception occurred during DllMain execution");
			ok = FALSE;
		}
		return ok;
	}

	// ---------- Hardware Spoofing ----------
	std::string GenerateRandomHardwareData()
	{
		srand((unsigned)time(nullptr));
		auto spoof = [](int base, int delta) { return base + (rand() % (2 * delta + 1) - delta); };

		int vramKB = spoof(16609312, 512);
		int ramGB = spoof(12, 1);
		int cores = spoof(12, 1);
		int threads = spoof(5, 1);
		unsigned hwid = (unsigned)spoof(0x000A0671, 0x10);

		char buffer[512];
		_snprintf_s(buffer, _TRUNCATE,
			"NVIDIA GeForce RTX 3060 Ti %d KB %d 4-0-%d-%d 11th Gen Intel(R) Core(TM) i5-11400F @ 2.60GHz 0x%08X 0xBFEBFBFF 0x7FFAFBBF",
			vramKB, ramGB, cores, threads, hwid);

		return std::string(buffer);
	}

	std::string SpoofCommandHWData(const std::string& input)
	{
		try
		{
			std::regex pattern(R"(\/(buto|quto).*?0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8})");
			if (!std::regex_search(input, pattern)) return input;

			std::string output = input;

			// Apply hardware spoofing transformations
			output = std::regex_replace(output,
				std::regex(R"(\b(?:NVIDIA|AMD|Intel).*?(?:RTX|GTX|Radeon|Arc).*?\b)"),
				"NVIDIA GeForce RTX 3060 Ti");

			// Spoof memory information
			output = std::regex_replace(output, std::regex(R"(\b\d{7,9} KB\b)"), "16609312 KB");

			return output;
		}
		catch (const std::regex_error& e)
		{
			te::sdk::helper::logging::Log("[REGEX ERROR] %s", e.what());
		}
		catch (const std::exception& e)
		{
			te::sdk::helper::logging::Log("[EXCEPTION] %s", e.what());
		}
		catch (...)
		{
			te::sdk::helper::logging::Log("[UNKNOWN ERROR] An unknown error occurred while processing the command.");
		}
		return input;
	}

	// ---------- Export Resolution ----------
	FARPROC GetExportedFunction(void* moduleBase, const char* functionName)
	{
		if (!moduleBase || !functionName || !*functionName) return nullptr;

		auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(moduleBase);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

		auto nt = reinterpret_cast<PIMAGE_NT_HEADERS32>((uint8_t*)moduleBase + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

		auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (!dir.VirtualAddress || !dir.Size) return nullptr;

		auto exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)moduleBase + dir.VirtualAddress);
		auto names = reinterpret_cast<DWORD*>((uint8_t*)moduleBase + exp->AddressOfNames);
		auto funcs = reinterpret_cast<DWORD*>((uint8_t*)moduleBase + exp->AddressOfFunctions);
		auto ords = reinterpret_cast<WORD*>((uint8_t*)moduleBase + exp->AddressOfNameOrdinals);

		for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
			const char* name = reinterpret_cast<const char*>((uint8_t*)moduleBase + names[i]);
			if (lstrcmpA(name, functionName) == 0) {
				WORD ord = ords[i];
				DWORD rva = funcs[ord];
				return (FARPROC)((uint8_t*)moduleBase + rva);
			}
		}
		return nullptr;
	}

	static SendCommandFunc ResolveSendCommand(HMODULE hMod)
	{
		if (!hMod) return nullptr;

		FARPROC p = GetExportedFunction(hMod, "SendCommand");
		if (p) {
			te::sdk::helper::logging::Log("[SendCommand] Found export 'SendCommand' at %p", p);
			return (SendCommandFunc)p;
		}

		const char* altNames[] = {
			"sendCommand", "send_command", "SendCmd", "_SendCommand"
		};

		for (const char* name : altNames) {
			p = GetExportedFunction(hMod, name);
			if (p) {
				te::sdk::helper::logging::Log("[SendCommand] Found export '%s' at %p", name, p);
				return (SendCommandFunc)p;
			}
		}

		te::sdk::helper::logging::Log("[SendCommand] Export not found");
		return nullptr;
	}

	// ---------- Hook Functions ----------
	int __cdecl Hooked_SendCommand(const char* str)
	{
		if (str) {
			__try {
				te::sdk::helper::logging::Log("[SendCommand] param=\"%s\"", str);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				te::sdk::helper::logging::Log("[SendCommand] param=<invalid pointer>");
			}
		}
		else {
			te::sdk::helper::logging::Log("[SendCommand] param=NULL");
		}

		return g_SendCommand ? g_SendCommand(str) : -1;
	}

	int __stdcall Hooked_ChatPush(int a1)
	{
		if (a1) {
			char buffer[1024] = { 0 };
			size_t actualLength = 0;

			if (SafeExtractString(a1, buffer, sizeof(buffer), &actualLength)) {
				std::string command = std::string(buffer, actualLength);
				command = SpoofCommandHWData(command);
				te::sdk::helper::logging::Log("[FenixZone AC Bypass] Processed command: %s", command.c_str());

				if (g_SendCommand) {
					return g_SendCommand(command.c_str());
				}
			}
		}

		return g_ChatPush_Orig ? g_ChatPush_Orig(a1) : 0;
	}

	static void __cdecl ServerComm_Impl(int a1_ebp, const void* a2_esi)
	{
		if (a2_esi) {
			char preview[64] = {};
			__try {
				memcpy(preview, a2_esi, sizeof(preview) - 1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
			te::sdk::helper::logging::Log("[ServerComm] a1=0x%08X a2=\"%s\"", a1_ebp, preview);
		}
	}

	__declspec(naked) void Hooked_ServerComm()
	{
		__asm {
			pushfd
			pushad
			mov eax, ebp
			mov edx, esi
			push edx
			push eax
			call ServerComm_Impl
			add esp, 8
			popad
			popfd
			jmp g_ServerComm_Orig
		}
	}

	BOOL WINAPI Hooked_WriteFile(HANDLE h, LPCVOID buf, DWORD n, LPDWORD out, LPOVERLAPPED ov)
	{
		char name[MAX_PATH] = {};
		GetFinalPathNameByHandleA(h, name, MAX_PATH, FILE_NAME_NORMALIZED);
		if (strstr(name, "Hyisdnga.tmp")) {
			SetLastError(ERROR_ACCESS_DENIED);
			return FALSE;
		}
		return g_WriteFile_Orig(h, buf, n, out, ov);
	}

	VOID WINAPI Hooked_ExitProcess(UINT code)
	{
		te::sdk::helper::logging::Log("[ExitProcess] blocked code=0x%X (press END to allow)", code);
		while (!(GetAsyncKeyState(VK_END) & 0x8000)) Sleep(50);
		g_ExitProcess_Orig(code);
	}

	BOOL WINAPI Hooked_TerminateProcess(HANDLE hProc, UINT code)
	{
		if (GetProcessId(hProc) == GetCurrentProcessId()) {
			te::sdk::helper::logging::Log("[TerminateProcess] blocked code=0x%X (press END to allow)", code);
			while (!(GetAsyncKeyState(VK_END) & 0x8000)) Sleep(50);
		}
		return g_TerminateProcess_Orig(hProc, code);
	}

	// ---------- CreateThread Patching ----------
	bool Patch_AllCreateThreadInFunction(uintptr_t funcAddr)
	{
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery(reinterpret_cast<void*>(funcAddr), &mbi, sizeof(mbi))) {
			te::sdk::helper::logging::Log("[Bypass] Failed to query memory at 0x%p", (void*)funcAddr);
			return true;
		}

		if (mbi.State != MEM_COMMIT ||
			!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
			te::sdk::helper::logging::Log("[Bypass] Memory at 0x%p is not executable", (void*)funcAddr);
			return true;
		}

		uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		uintptr_t regionEnd = regionStart + mbi.RegionSize;
		uintptr_t maxScanEnd = funcAddr + 0x1000;

		if (maxScanEnd > regionEnd) {
			maxScanEnd = regionEnd;
		}

		size_t funcSize = maxScanEnd - funcAddr;
		if (funcSize < 16) {
			te::sdk::helper::logging::Log("[Bypass] Function size too small: 0x%X bytes", (unsigned)funcSize);
			return true;
		}

		auto code = reinterpret_cast<uint8_t*>(funcAddr);
		int patched = 0;

		HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
		if (!hKernel32) return true;

		FARPROC pCreateThread = GetProcAddress(hKernel32, "CreateThread");
		if (!pCreateThread) return true;

		__try {
			for (size_t i = 0; i + 5 <= funcSize; ++i)
			{
				if (code[i] == 0xE8) // CALL instruction
				{
					int32_t rel = *reinterpret_cast<int32_t*>(&code[i + 1]);
					uintptr_t callTarget = funcAddr + i + 5 + rel;

					if (callTarget < 0x10000 || callTarget > 0x7FFFFFFF) continue;

					if (callTarget == reinterpret_cast<uintptr_t>(pCreateThread))
					{
						DWORD oldProtect;
						if (VirtualProtect(&code[i], 5, PAGE_EXECUTE_READWRITE, &oldProtect))
						{
							memset(&code[i], 0x90, 5); // NOP
							VirtualProtect(&code[i], 5, oldProtect, &oldProtect);
							++patched;
						}
						continue;
					}

					uint8_t thunkBytes[6];
					if (SafeReadMemory(reinterpret_cast<void*>(callTarget), thunkBytes, 6))
					{
						if (thunkBytes[0] == 0xFF && thunkBytes[1] == 0x25)
						{
							uint32_t importAddr = *reinterpret_cast<uint32_t*>(&thunkBytes[2]);
							uint32_t finalTarget;

							if (SafeReadMemory(reinterpret_cast<void*>(importAddr), &finalTarget, 4))
							{
								if (finalTarget == reinterpret_cast<uintptr_t>(pCreateThread))
								{
									DWORD oldProtect;
									if (VirtualProtect(&code[i], 5, PAGE_EXECUTE_READWRITE, &oldProtect))
									{
										memset(&code[i], 0x90, 5);
										VirtualProtect(&code[i], 5, oldProtect, &oldProtect);
										++patched;
									}
								}
							}
						}
					}
				}
				else if (i + 6 <= funcSize && code[i] == 0xFF && code[i + 1] == 0x15)
				{
					uint32_t ptrAddr = *reinterpret_cast<uint32_t*>(&code[i + 2]);

					if (ptrAddr >= 0x10000 && ptrAddr <= 0x7FFFFFFF)
					{
						uint32_t targetAddr;
						if (SafeReadMemory(reinterpret_cast<void*>(ptrAddr), &targetAddr, 4))
						{
							if (targetAddr == reinterpret_cast<uintptr_t>(pCreateThread))
							{
								DWORD oldProtect;
								if (VirtualProtect(&code[i], 6, PAGE_EXECUTE_READWRITE, &oldProtect))
								{
									memset(&code[i], 0x90, 6);
									VirtualProtect(&code[i], 6, oldProtect, &oldProtect);
									++patched;
									i += 5;
								}
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			te::sdk::helper::logging::Log("[Bypass] Exception during scanning at 0x%p", (void*)funcAddr);
		}

		te::sdk::helper::logging::Log("[Bypass] Patched %d CreateThread calls", patched);
		return true;
	}

	// ---------- Hook Installation ----------
	static bool InstallAllHooks(HMODULE mappedCommDll, HMODULE mappedMainDll)
	{
		LONG err = DetourTransactionBegin();
		if (err != NO_ERROR) return false;
		DetourUpdateThread(GetCurrentThread());

		// SendCommand from comm DLL
		if (mappedCommDll) {
			g_SendCommand = ResolveSendCommand(mappedCommDll);
			if (g_SendCommand) {
				DetourAttach(&(PVOID&)g_SendCommand, Hooked_SendCommand);
				te::sdk::helper::logging::Log("[detours] SendCommand hooked @%p", g_SendCommand);
			}
		}

		// ChatPush from main DLL
		if (mappedMainDll) {
			auto chatPushAddr = (ChatPushFunc)PatternScanModule(mappedMainDll, SIG_FENIXZONE_CHAT_PUSH);
			if (chatPushAddr) {
				g_ChatPush_Orig = chatPushAddr;
				DetourAttach(&(PVOID&)g_ChatPush_Orig, Hooked_ChatPush);
				te::sdk::helper::logging::Log("[detours] ChatPush hooked @%p", chatPushAddr);
			}

			auto serverCommAddr = (ServerCommFunc)PatternScanModule(mappedMainDll, SIG_SERVER_COMMUNICATION);
			if (serverCommAddr) {
				g_ServerComm_Orig = serverCommAddr;
				DetourAttach(&(PVOID&)g_ServerComm_Orig, Hooked_ServerComm);
				te::sdk::helper::logging::Log("[detours] ServerComm hooked @%p", serverCommAddr);
			}
		}

		// System APIs
		HMODULE hK32 = GetModuleHandleA("kernel32.dll");
		if (hK32) {
			g_WriteFile_Orig = (WriteFileFunc)GetProcAddress(hK32, "WriteFile");
			//g_ExitProcess_Orig = (ExitProcessFunc)GetProcAddress(hK32, "ExitProcess");
			//g_TerminateProcess_Orig = (TerminateProcessFunc)GetProcAddress(hK32, "TerminateProcess");

			if (g_WriteFile_Orig) DetourAttach(&(PVOID&)g_WriteFile_Orig, Hooked_WriteFile);
			if (g_ExitProcess_Orig) DetourAttach(&(PVOID&)g_ExitProcess_Orig, Hooked_ExitProcess);
			if (g_TerminateProcess_Orig) DetourAttach(&(PVOID&)g_TerminateProcess_Orig, Hooked_TerminateProcess);
		}

		err = DetourTransactionCommit();
		if (err != NO_ERROR) {
			te::sdk::helper::logging::Log("[detours] commit failed: %ld", err);
			return false;
		}
		return true;
	}

	static void UninstallAllHooks()
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		if (g_SendCommand) DetourDetach(&(PVOID&)g_SendCommand, Hooked_SendCommand);
		if (g_ChatPush_Orig) DetourDetach(&(PVOID&)g_ChatPush_Orig, Hooked_ChatPush);
		if (g_ServerComm_Orig) DetourDetach(&(PVOID&)g_ServerComm_Orig, Hooked_ServerComm);
		if (g_WriteFile_Orig) DetourDetach(&(PVOID&)g_WriteFile_Orig, Hooked_WriteFile);
		if (g_ExitProcess_Orig) DetourDetach(&(PVOID&)g_ExitProcess_Orig, Hooked_ExitProcess);
		if (g_TerminateProcess_Orig) DetourDetach(&(PVOID&)g_TerminateProcess_Orig, Hooked_TerminateProcess);

		DetourTransactionCommit();
	}

	// ---------- Command Emulation ----------
	static uint8_t GetMessageNumberValue(HMODULE hMod)
	{
		static uintptr_t addrMessageNumber = 0;

		if (!addrMessageNumber) {
			uintptr_t sigAddr = PatternScanModule(hMod, SIG_MESSAGE_NUMBER);
			if (!sigAddr) {
				te::sdk::helper::logging::Log("[GetMessageNumber] Signature not found");
				return 0;
			}
			addrMessageNumber = *reinterpret_cast<uintptr_t*>(sigAddr + 2);
		}

		return *reinterpret_cast<uint8_t*>(addrMessageNumber);
	}

	static std::string GenerateDRAString()
	{
		char expandedPath[MAX_PATH];
		DWORD result = ExpandEnvironmentStringsA("%PUBLIC%\\Pictures", expandedPath, MAX_PATH);

		if (result == 0) {
			// Fallback to default path if expansion fails
			strcpy(expandedPath, "C:\\Users\\Public\\Pictures");
		}

		// Create search pattern for dRA* files/folders
		char searchPattern[MAX_PATH];
		sprintf(searchPattern, "%s\\dRA*", expandedPath);

		WIN32_FIND_DATAA findData;
		HANDLE hFind = FindFirstFileA(searchPattern, &findData);

		std::string draString;

		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				std::string fileName = findData.cFileName;

				// Check if this starts with "dRA" (case-sensitive)
				if (fileName.length() > 3 && fileName.substr(0, 3) == "dRA") {
					draString = fileName;
					break; // Take the first match
				}
			} while (FindNextFileA(hFind, &findData));

			FindClose(hFind);
		}
		else {
			DWORD error = GetLastError();
			te::sdk::helper::logging::Log("[DRA Generator] FindFirstFileA failed with error: %d", error);
		}
		return draString;
	}

	void EmulateCommands(HMODULE hMod)
	{
		if (!g_SendCommand) {
			te::sdk::helper::logging::Log("[EMULATOR] g_SendCommand not set");
			return;
		}

		srand((unsigned)time(nullptr));
		auto spoof = [](int base, int delta) { return base + (rand() % (2 * delta + 1) - delta); };

		int vramKB = spoof(16609312, 512);
		int ramGB = spoof(12, 1);
		int cores = spoof(12, 1);
		int threads = spoof(5, 1);
		unsigned hwid = (unsigned)spoof(0x000A0671, 0x10);

		uint8_t msgNum = GetMessageNumberValue(hMod);

		char cmd1[512];
		_snprintf_s(cmd1, _TRUNCATE,
			"/buto CLA: NVIDIA GeForce RTX 3060 Ti %d KB %d 4-0-%d-%d 11th Gen Intel(R) Core(TM) i5-11400F @ 2.60GHz 0x%08X 0xBFEBFBFF 0x7FFAFBBF",
			vramKB, ramGB, cores, threads, hwid);

		char cmd2[64];
		_snprintf_s(cmd2, _TRUNCATE, "/buto DRA: %s", GenerateDRAString().c_str());

		char cmd3[512];
		_snprintf_s(cmd3, _TRUNCATE,
			"/quto MON: NVIDIA GeForce RTX 3060 Ti %d 4-0-%d-%d 11th Gen Intel(R) Core(TM) i5-11400F @ 2.60GHz AUS278F 598X336",
			ramGB, cores, threads);

		char cmd4[32];
		_snprintf_s(cmd4, _TRUNCATE, "/cuco %u", msgNum);

		struct Cmd { const char* text; DWORD delay; };
		Cmd cmds[] = {
			{ cmd1, 1501 },
			{ cmd2, 2000 },
			{ cmd3, 1001 },
			{ cmd4, 1001 },
		};

		for (auto& c : cmds) {
			te::sdk::helper::logging::Log("[EMULATOR] Sending: %s", c.text);
			g_SendCommand(c.text);
			Sleep(c.delay);
		}
	}

	// ---------- Manual Mapping ----------
	ManualMapResult ManualMapDllFromMemory(const std::vector<uint8_t>& dllBytes)
	{
		ManualMapResult result{};

		if (dllBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
			te::sdk::helper::logging::Log("[ManualMap] Input buffer too small for IMAGE_DOS_HEADER");
			return result;
		}

		if (dllBytes[0] == 'A' && dllBytes[1] == 'X') {
			te::sdk::helper::logging::Log("[ManualMap] Obfuscated AX header detected, converting to MZ");
			const_cast<uint8_t&>(dllBytes[0]) = 'M';
			const_cast<uint8_t&>(dllBytes[1]) = 'Z';
		}

		const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			te::sdk::helper::logging::Log("[ManualMap] Invalid DOS signature (expected MZ)");
			return result;
		}

		const auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(
			dllBytes.data() + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
			te::sdk::helper::logging::Log("[ManualMap] Invalid NT signature (expected PE)");
			return result;
		}

		const auto& optional = ntHeader->OptionalHeader;
		const SIZE_T sizeOfImage = optional.SizeOfImage;
		const SIZE_T sizeOfHeaders = optional.SizeOfHeaders;

		te::sdk::helper::logging::Log("[ManualMap] Mapping image of size 0x%X (headers: 0x%X)",
			(unsigned)sizeOfImage, (unsigned)sizeOfHeaders);

		LPVOID baseAddress = VirtualAlloc(reinterpret_cast<LPVOID>(optional.ImageBase),
			sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!baseAddress) {
			te::sdk::helper::logging::Log("[ManualMap] Failed to allocate at preferred base 0x%p, trying anywhere",
				(void*)optional.ImageBase);
			baseAddress = VirtualAlloc(nullptr, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!baseAddress) {
				te::sdk::helper::logging::Log("[ManualMap] VirtualAlloc failed");
				return result;
			}
		}

		te::sdk::helper::logging::Log("[ManualMap] Allocated image at 0x%p", baseAddress);
		result.imageBase = baseAddress;
		result.imageSize = sizeOfImage;

		// Copy headers
		std::memcpy(baseAddress, dllBytes.data(), sizeOfHeaders);

		// Copy sections
		auto* section = IMAGE_FIRST_SECTION(ntHeader);
		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section) {
			if (!section->SizeOfRawData) continue;
			void* dest = reinterpret_cast<uint8_t*>(baseAddress) + section->VirtualAddress;
			const void* src = dllBytes.data() + section->PointerToRawData;
			std::memcpy(dest, src, section->SizeOfRawData);
			te::sdk::helper::logging::Log("[ManualMap] Copied section %.*s to 0x%p (size: 0x%X)",
				8, section->Name, dest, section->SizeOfRawData);
		}

		// Resolve imports
		if (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
			auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
				reinterpret_cast<uint8_t*>(baseAddress) +
				optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			while (importDesc->Name) {
				const char* dllName = reinterpret_cast<const char*>(
					reinterpret_cast<uint8_t*>(baseAddress) + importDesc->Name);

				HMODULE hDll = LoadLibraryA(dllName);
				if (!hDll) {
					te::sdk::helper::logging::Log("[ManualMap] Failed to LoadLibraryA: %s", dllName);
					return result;
				}
				te::sdk::helper::logging::Log("[ManualMap] Loaded import: %s", dllName);

				auto* thunkRef = reinterpret_cast<IMAGE_THUNK_DATA*>(
					reinterpret_cast<uint8_t*>(baseAddress) + importDesc->FirstThunk);
				auto* origThunkRef = reinterpret_cast<IMAGE_THUNK_DATA*>(
					reinterpret_cast<uint8_t*>(baseAddress) + importDesc->OriginalFirstThunk);

				while (thunkRef->u1.AddressOfData) {
					FARPROC func = nullptr;
					if (origThunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
						func = GetProcAddress(hDll, reinterpret_cast<LPCSTR>(origThunkRef->u1.Ordinal & 0xFFFF));
					}
					else {
						auto* importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
							reinterpret_cast<uint8_t*>(baseAddress) + origThunkRef->u1.AddressOfData);
						func = GetProcAddress(hDll, importByName->Name);
					}

					if (!func) {
						te::sdk::helper::logging::Log("[ManualMap] Failed to resolve import");
						return result;
					}

					thunkRef->u1.Function = reinterpret_cast<ULONG_PTR>(func);
					++thunkRef;
					++origThunkRef;
				}

				++importDesc;
			}
		}

		// Apply relocations
		if (reinterpret_cast<uintptr_t>(baseAddress) != optional.ImageBase &&
			optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {

			uintptr_t delta = reinterpret_cast<uintptr_t>(baseAddress) - optional.ImageBase;

			auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<uint8_t*>(baseAddress) +
				optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while (reloc->VirtualAddress) {
				DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* relocData = reinterpret_cast<WORD*>(reloc + 1);

				for (DWORD i = 0; i < count; ++i) {
					WORD typeOffset = relocData[i];
					WORD type = typeOffset >> 12;
					WORD offset = typeOffset & 0x0FFF;

					if (type == IMAGE_REL_BASED_HIGHLOW) {
						auto* patchAddr = reinterpret_cast<DWORD*>(
							reinterpret_cast<uint8_t*>(baseAddress) + reloc->VirtualAddress + offset);
						*patchAddr += static_cast<DWORD>(delta);
					}
				}

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
					reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
			}

			te::sdk::helper::logging::Log("[ManualMap] Relocations applied (delta: 0x%p)", (void*)delta);
		}

		// Set entry point
		result.entryPoint = (optional.AddressOfEntryPoint != 0)
			? reinterpret_cast<void*>(reinterpret_cast<uint8_t*>(baseAddress) + optional.AddressOfEntryPoint)
			: nullptr;

		te::sdk::helper::logging::Log("[ManualMap] Mapping complete. Entry point at 0x%p", result.entryPoint);
		return result;
	}

	// ---------- File Path Resolution ----------
	struct FzPaths {
		std::string acBin;
		std::string commFz;
	};

	static FzPaths ResolveFzPaths()
	{
		FzPaths p;

		char path[MAX_PATH];
		DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
		if (len == 0 || len == MAX_PATH) {
			te::sdk::helper::logging::Log("[paths] Failed to get module path, using defaults");
			p.acBin = "rce_protection\\fz_bypass\\anticheat.fz";
			p.commFz = "rce_protection\\fz_bypass\\comm.fz";
			return p;
		}

		std::string basePath(path);
		size_t lastSlash = basePath.find_last_of("\\/");
		if (lastSlash != std::string::npos) {
			basePath = basePath.substr(0, lastSlash + 1);
		}

		p.acBin = basePath + "rce_protection\\fz_bypass\\anticheat.fz";
		p.commFz = basePath + "rce_protection\\fz_bypass\\comm.fz";

		te::sdk::helper::logging::Log("[paths] acBin = %s", p.acBin.c_str());
		te::sdk::helper::logging::Log("[paths] commFz = %s", p.commFz.c_str());
		return p;
	}

	// ---------- Worker Thread ----------
	DWORD WINAPI Worker(LPVOID)
	{
		te::sdk::helper::logging::Log("[worker] Starting FenixZone bypass initialization");

		auto paths = ResolveFzPaths();
		std::vector<uint8_t> bytesComm;
		std::vector<uint8_t> bytesAC;

		if (!ReadFileToVector(paths.commFz, bytesComm, "comm")) {
			te::sdk::helper::logging::Log("[worker] Cannot read comm.fz -> abort");
			te::sdk::helper::samp::AddChatMessage("[#TE] Failed to load FenixZone communication module", D3DCOLOR_XRGB(255, 0, 0));
			return 1;
		}

		if (!ReadFileToVector(paths.acBin, bytesAC, "ac")) {
			te::sdk::helper::logging::Log("[worker] WARN: ac bin not loaded, will install only comm/WinAPI hooks");
			bytesAC.clear();
		}

		ManualMapResult mmComm = ManualMapDllFromMemory(bytesComm);
		if (!mmComm.imageBase || !mmComm.entryPoint) {
			te::sdk::helper::logging::Log("[worker] Manual map COMM failed");
			te::sdk::helper::samp::AddChatMessage("[#TE] Failed to map communication module", D3DCOLOR_XRGB(255, 0, 0));
			return 1;
		}
		te::sdk::helper::logging::Log("[worker] COMM mapped @ %p, size=%zu, ep=%p", mmComm.imageBase, mmComm.imageSize, mmComm.entryPoint);

		ManualMapResult mmAC{};
		if (!bytesAC.empty()) {
			mmAC = ManualMapDllFromMemory(bytesAC);
			if (!mmAC.imageBase || !mmAC.entryPoint) {
				te::sdk::helper::logging::Log("[worker] WARN: AC map failed, continuing with COMM only");
				mmAC = {};
			}
			else {
				te::sdk::helper::logging::Log("[worker] AC mapped @ %p, size=%zu, ep=%p", mmAC.imageBase, mmAC.imageSize, mmAC.entryPoint);
			}
		}

		HMODULE hComm = (HMODULE)mmComm.imageBase;
		HMODULE hAC = (HMODULE)mmAC.imageBase;

		// Patch CreateThread calls before installing hooks
		if (mmComm.entryPoint) {
			if (!Patch_AllCreateThreadInFunction(reinterpret_cast<uintptr_t>(mmComm.entryPoint))) {
				te::sdk::helper::logging::Log("[worker] Failed to patch CreateThread in COMM module");
				return 1;
			}
		}

		// Patch CreateThread calls before installing hooks
		if (mmAC.entryPoint) {
			if (!Patch_AllCreateThreadInFunction(reinterpret_cast<uintptr_t>(mmAC.entryPoint))) {
				te::sdk::helper::logging::Log("[worker] Failed to patch CreateThread in AC module");
				return 1;
			}
		}

		if (!InstallAllHooks(hComm, hAC)) {
			te::sdk::helper::logging::Log("[worker] InstallAllHooks failed");
			te::sdk::helper::samp::AddChatMessage("[#TE] Failed to install hooks", D3DCOLOR_XRGB(255, 0, 0));
			return 1;
		}

		te::sdk::helper::logging::Log("[worker] Hooks installed successfully");

		// Call DllMain for COMM module
		if (mmComm.entryPoint && mmComm.imageBase) {
			if (!SafeCallDllMain(mmComm.entryPoint, mmComm.imageBase)) {
				te::sdk::helper::logging::Log("[worker] COMM DllMain attach failed");
				return 1;
			}
		}

		// Call DllMain for AC module
		if (mmAC.entryPoint && mmAC.imageBase) {
			if (!SafeCallDllMain(mmAC.entryPoint, mmAC.imageBase)) {
				te::sdk::helper::logging::Log("[worker] AC DllMain attach failed (continuing)");
			}
		}

		// Emulate commands
		EmulateCommands(hAC);

		te::sdk::helper::logging::Log("[worker] FenixZone AC bypass initialized successfully");
		te::sdk::helper::samp::AddChatMessage("[#TE] FenixZone Anti Cheat bypassed successfully!", D3DCOLOR_XRGB(128, 235, 52));
		return 0;
	}

	// ---------- BitStream Processing ----------
	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName)
	{
		int originalOffset = bs->GetReadOffset();
		size_t totalBytes = bs->GetNumberOfBytesUsed();
		std::vector<unsigned char> allData(totalBytes);

		bs->SetReadOffset(0);
		bs->Read((char*)allData.data(), totalBytes);
		bs->SetReadOffset(originalOffset);

		// Search for MZ header
		size_t mzOffset = 0;
		bool foundMZ = false;

		for (size_t i = 0; i < allData.size() - 1; i++)
		{
			if (allData[i] == 0x4D && allData[i + 1] == 0x5A)
			{
				foundMZ = true;
				mzOffset = i;
				break;
			}
		}

		if (!foundMZ) {
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] No MZ header found in BitStream data.");
			return false;
		}

		// Verify PE signature
		if (mzOffset + 0x40 >= allData.size()) {
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] Not enough data after MZ header.");
			return false;
		}

		uint32_t peOffset = 0;
		if (mzOffset + 0x3C + sizeof(uint32_t) <= allData.size()) {
			peOffset = *reinterpret_cast<uint32_t*>(&allData[mzOffset + 0x3C]);
		}

		bool isPEFile = false;
		if (mzOffset + peOffset + 4 <= allData.size()) {
			isPEFile = (allData[mzOffset + peOffset] == 'P' &&
				allData[mzOffset + peOffset + 1] == 'E' &&
				allData[mzOffset + peOffset + 2] == 0 &&
				allData[mzOffset + peOffset + 3] == 0);
		}

		if (isPEFile) {
			std::vector<unsigned char> exeData(allData.begin() + mzOffset, allData.end());

			try {
				auto testSig = helper::PatternScan(reinterpret_cast<uint32_t>(exeData.data()), "A1 ? ? ? ? 83 F8 FF", false);
				if (testSig != NULL) {
					te::sdk::helper::logging::Log("Detected FenixZone server, preparing bypass... (rpcId: %i (%s))",
						rpcId, rpcName.c_str());

					// Start bypass in worker thread
					CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
					return true;
				}
				else {
					te::sdk::helper::logging::Log("FenixZone server not detected, skipping.");
				}
				return true;
			}
			catch (const std::exception& e) {
				te::sdk::helper::logging::Log("Exception while processing PE executable: %s", e.what());
			}
		}

		return false;
	}
}