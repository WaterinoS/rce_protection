#include "te-fz-bypass.h"
#include "te-rce-protection.h"

#include <d3d9.h>
#include <vector>
#include <string>
#include <regex>

#include "Detours/detours_x86.h"
#pragma comment(lib, "Detours/detours_x86.lib")

namespace te::rce::fz::bypass
{
	struct ManualMapResult {
		void* imageBase = nullptr;
		void* entryPoint = nullptr;
	};

	struct ChatPushHook {
		uintptr_t originalFunction = 0;
		uintptr_t hookFunction = 0;
		BYTE originalBytes[32] = { 0 };
		BYTE* trampoline = nullptr;
		bool isHooked = false;
	};

	// Signatures
	constexpr auto SIG_FENIXZONE_CHAT_PUSH = "55 0F BA FD 27 F5 89 E5 57 F9 66 F7 C6 ? ? 3B D6 56 8D B5 ? ? ? ? E9 ? ? ? ?";

	// Global variables
	uintptr_t g_mappedBase = 0;
	uintptr_t g_entryRVA = 0;
	uintptr_t g_stubEP = 0;
	uintptr_t g_stubScanSize = 0x300;
	ChatPushHook g_chatPushHook;

	// Other
	std::unordered_map<std::string, PatternData> s_patternCache;
	static std::recursive_mutex g_memoryProtectionMutex;

	bool SafeVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		std::lock_guard<std::recursive_mutex> lock(g_memoryProtectionMutex);
		return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) != FALSE;
	}

	BOOL SafeExtractString(int address, char* buffer, size_t bufferSize, size_t* actualLength)
	{
		*actualLength = 0;

		if (address == 0 || bufferSize == 0) {
			return FALSE;
		}

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

	int SafeCallOriginalFunction(void* trampoline, int parameter)
	{
		if (!trampoline) {
			return -1;
		}

		__try {
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery(trampoline, &mbi, sizeof(mbi)) ||
				mbi.State != MEM_COMMIT ||
				!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
				return -1;
			}

			typedef int(__stdcall* OriginalChatPushFunc)(int);
			OriginalChatPushFunc originalFunc = reinterpret_cast<OriginalChatPushFunc>(trampoline);

			return originalFunc(parameter);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return -1;
		}
	}

	std::string RandomHex()
	{
		std::stringstream ss;
		ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (rand() & 0xFFFFFFFF);
		return ss.str();
	}

	std::string RandomMonitorID()
	{
		static const char* vendors[] = {"AUO", "CMN", "LGD", "SHP", "BOE"};
		int vendorIdx = rand() % 5;
		int code = 1000 + rand() % 9000;
		return vendors[vendorIdx] + std::to_string(code);
	}

	std::string RandomResolution()
	{
		static const char* resolutions[] = {"1920X1080", "2560X1440", "1366X768", "1600X900", "3440X1440"};
		return resolutions[rand() % 5];
	}

	std::string RandomRAM()
	{
		int ramMb = (8 + rand() % 24) * 1024;
		return std::to_string(ramMb * 1024) + " KB";
	}

	std::string RandomCPU()
	{
		static const char* cpus[] = {
			"Intel(R) Core(TM) i9-14900K", "AMD Ryzen 9 5900X",
			"Intel(R) Core(TM) i5-12600H", "AMD Ryzen 7 7840HS"
		};
		return cpus[rand() % 4];
	}

	bool IsSpoofableCommand(const std::string& line)
	{
		std::regex pattern(R"(\/(buto|quto).*?0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8})");
		return std::regex_search(line, pattern);
	}

	std::string ReplaceHexWithRandom(const std::string& input)
	{
		std::smatch match;
		std::regex hexRegex(R"(0x[0-9A-Fa-f]{8})");
		std::string result;
		auto searchStart(input.cbegin());

		while (std::regex_search(searchStart, input.cend(), match, hexRegex))
		{
			result.append(searchStart, match[0].first);
			result.append(RandomHex());
			searchStart = match[0].second;
		}
		result.append(searchStart, input.cend());
		return result;
	}

	std::string GetRandomDisplayDevice()
	{
		static const char* displayDevices[] = {
			"NVIDIA GeForce RTX 4080", "AMD Radeon RX 7900 XTX",
			"NVIDIA GeForce RTX 3070", "AMD Radeon RX 6800 XT",
			"NVIDIA GeForce GTX 1660 Ti", "AMD Radeon RX 5700 XT"
		};
		return displayDevices[rand() % 6];
	}

	std::string GetRandomCPUBrand()
	{
		char cpuBrand[48] = {};
		// Simulate random CPU brand string from CPUID
		static const char* brands[] = {
			"GenuineIntel", "AuthenticAMD", "CentaurHauls"
		};
		strcpy(cpuBrand, brands[rand() % 3]);
		return std::string(cpuBrand);
	}

	std::string GenerateRandomCPUID()
	{
		// Generate random CPUID values similar to the assembly function
		uint32_t eax = 0x00000001 + (rand() & 0xFFFF);
		uint32_t edx = 0x078BFBFF + (rand() & 0xFFFF);
		uint32_t ecx = 0x7FFAFBBF + (rand() & 0xFFFF);

		char buffer[64];
		snprintf(buffer, sizeof(buffer), "0x%08X 0x%08X 0x%08X", eax, edx, ecx);
		return std::string(buffer);
	}

	std::string SpoofCommandHWData(const std::string& input)
	{
		try
		{
			if (!IsSpoofableCommand(input))
			{
				return input;
			}

			std::string output = input;

			// Spoof display device information (like EnumDisplayDevicesA)
			output = std::regex_replace(output,
			                            std::regex(R"(\b(?:NVIDIA|AMD|Intel).*?(?:RTX|GTX|Radeon|Arc).*?\b)"),
			                            GetRandomDisplayDevice());

			// Spoof memory information (like GlobalMemoryStatusEx)
			output = std::regex_replace(output, std::regex(R"(\b\d{7,9} KB\b)"), RandomRAM());

			// Spoof processor count (like GetSystemInfo)
			output = std::regex_replace(output,
			                            std::regex(R"(\b(\d{1,2})(?= \d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}))"),
			                            std::to_string(4 + rand() % 13)); // 4-16 processors

			// Spoof keyboard type information (like GetKeyboardType calls)
			output = std::regex_replace(output,
			                            std::regex(R"(\b\d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}\b)"),
			                            std::to_string(4 + rand() % 4) + "-" + // Keyboard type (4-7)
			                            std::to_string(rand() % 12) + "-" + // Keyboard subtype (0-11)
			                            std::to_string(1 + rand() % 12) + "-" + // Function keys (1-12)
			                            std::to_string(43 + rand() % 10)); // System metrics variation

			// Spoof CPU brand string (from CPUID)
			output = std::regex_replace(output,
			                            std::regex(R"(\b(?:GenuineIntel|AuthenticAMD|CentaurHauls)\b)"),
			                            GetRandomCPUBrand());

			// Spoof CPU model information
			output = std::regex_replace(output,
			                            std::regex(R"((\d+(?:th)? Gen .+? Core\(TM\) .+?))"),
			                            RandomCPU());

			// Spoof CPUID register values (the 0x08X format from assembly)
			output = std::regex_replace(output,
			                            std::regex(R"(0x[0-9A-Fa-f]{8} 0x[0-9A-Fa-f]{8} 0x[0-9A-Fa-f]{8})"),
			                            GenerateRandomCPUID());

			// Spoof individual hex values
			output = ReplaceHexWithRandom(output);

			// Spoof monitor information
			output = std::regex_replace(output, std::regex(R"(\b[A-Z]{3}\d{4}\b)"), RandomMonitorID());
			output = std::regex_replace(output, std::regex(R"(\b\d{3,4}X\d{3,4}\b)"), RandomResolution());

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

	int __stdcall HookedChatPush(int a1)
	{
		if (a1 != 0) {
			char buffer[1024] = { 0 };
			size_t actualLength = 0;

			if (SafeExtractString(a1, buffer, sizeof(buffer), &actualLength)) {
				std::string command = std::string(buffer, actualLength);
				command = SpoofCommandHWData(command);

				te::sdk::helper::logging::Log("[FenixZone AC Bypass] Processed command: %s", command.c_str());

				return SafeCallOriginalFunction(g_chatPushHook.trampoline, reinterpret_cast<int>(command.c_str()));
			}
		}

		return SafeCallOriginalFunction(g_chatPushHook.trampoline, a1);
	}

	bool InstallChatPushHook(uintptr_t moduleBase)
	{
		g_chatPushHook.originalFunction = helper::PatternScan(moduleBase, SIG_FENIXZONE_CHAT_PUSH, false);
		if (!g_chatPushHook.originalFunction) {
			sdk::helper::logging::Log("[ChatPush Hook] Failed to find function with signature");
			return false;
		}

		BYTE* funcBytes = reinterpret_cast<BYTE*>(g_chatPushHook.originalFunction);

		if (funcBytes[0] != 0x55) {
			sdk::helper::logging::Log("[ChatPush Hook] Function signature verification failed - missing push ebp");
			return false;
		}

		const size_t prologueSize = 24;
		const size_t hookSize = 29;

		memcpy(g_chatPushHook.originalBytes, funcBytes, hookSize);

		int32_t originalJmpOffset = *reinterpret_cast<int32_t*>(&funcBytes[25]); // offset po E9
		uintptr_t originalJmpTarget = g_chatPushHook.originalFunction + 29 + originalJmpOffset;

		g_chatPushHook.trampoline = static_cast<BYTE*>(VirtualAlloc(
			nullptr,
			64,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE
		));

		if (!g_chatPushHook.trampoline) {
			sdk::helper::logging::Log("[ChatPush Hook] Failed to allocate trampoline");
			return false;
		}

		memcpy(g_chatPushHook.trampoline, g_chatPushHook.originalBytes, prologueSize);

		BYTE* jumpToTarget = g_chatPushHook.trampoline + prologueSize;
		jumpToTarget[0] = 0xE9; // JMP instruction
		*reinterpret_cast<DWORD*>(jumpToTarget + 1) =
			originalJmpTarget - (reinterpret_cast<uintptr_t>(jumpToTarget) + 5);

		// Install the hook
		DWORD oldProtect;
		if (!VirtualProtect(funcBytes, hookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			sdk::helper::logging::Log("[ChatPush Hook] Failed to change memory protection");
			VirtualFree(g_chatPushHook.trampoline, 0, MEM_RELEASE);
			return false;
		}

		// Create the hook jump - we need exactly 5 bytes for the JMP
		funcBytes[0] = 0xE9; // JMP instruction
		*reinterpret_cast<DWORD*>(funcBytes + 1) =
			reinterpret_cast<uintptr_t>(HookedChatPush) - (g_chatPushHook.originalFunction + 5);

		for (size_t i = 5; i < hookSize; ++i) {
			funcBytes[i] = 0x90; // NOP
		}

		// Restore original protection
		VirtualProtect(funcBytes, hookSize, oldProtect, &oldProtect);

		g_chatPushHook.isHooked = true;
		sdk::helper::logging::Log("[ChatPush Hook] Successfully installed hook");

		return true;
	}

	static PatternData& ParsePattern(const char* sig)
	{
		auto it = s_patternCache.find(sig);
		if (it != s_patternCache.end()) return it->second;

		PatternData pd;
		const char* cur = sig;
		while (*cur)
		{
			if (*cur == '?')
			{
				++cur;
				if (*cur == '?') ++cur;
				pd.bytes.push_back(0);
				pd.mask.push_back(false);
			}
			else
			{
				pd.bytes.push_back(static_cast<uint8_t>(strtoul(cur, const_cast<char**>(&cur), 16)));
				pd.mask.push_back(true);
			}
			if (*cur == ' ') ++cur;
		}
		pd.firstWildcard = !pd.mask[0];
		pd.firstByte = pd.bytes[0];
		return s_patternCache.emplace(sig, std::move(pd)).first->second;
	}

	uintptr_t PatternScanRCEOnly(const char* signature, bool skipFirst = false)
	{
		auto& pat = ParsePattern(signature);
		size_t pLen = pat.bytes.size();
		if (pLen == 0) return 0;

		MEMORY_BASIC_INFORMATION mbi;
		uintptr_t address = 0;
		bool foundOnce = false;

		while (VirtualQuery((void*)address, &mbi, sizeof(mbi)) == sizeof(mbi))
		{
			if (mbi.State == MEM_COMMIT
				&& mbi.Type == MEM_PRIVATE
				&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				&& !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				auto* region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
				size_t regionSize = mbi.RegionSize;
				if (regionSize >= pLen)
				{
					const uint8_t* cur = region;
					const uint8_t* end = region + regionSize - pLen;

					while (cur <= end)
					{
						if (!pat.firstWildcard)
						{
							cur = static_cast<const uint8_t*>(memchr(cur, pat.firstByte, (end - cur) + 1));
							if (!cur) break;
						}
						bool ok = true;
						for (size_t j = 0; j < pLen; ++j)
						{
							if (pat.mask[j] && cur[j] != pat.bytes[j])
							{
								ok = false;
								break;
							}
						}
						if (ok)
						{
							if (skipFirst && !foundOnce)
							{
								foundOnce = true;
							}
							else
							{
								return uintptr_t(cur);
							}
						}
						++cur;
					}
				}
			}
			address += mbi.RegionSize;
		}
		return 0;
	}

	bool TryCreateHook(const char* name, uintptr_t sig, LPVOID hookFunc, LPVOID* original)
	{
		if (sig == 0)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] Signature for %s not found.", name);
			return false;
		}

		LONG error = NO_ERROR;

		// Set the original function pointer (Detours expects the original, NOT the address!)
		*original = reinterpret_cast<LPVOID>(sig);

		error = DetourTransactionBegin();
		if (error != NO_ERROR)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] DetourTransactionBegin failed for %s: %ld", name,
			                             error);
			return false;
		}

		error = DetourUpdateThread(GetCurrentThread());
		if (error != NO_ERROR)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] DetourUpdateThread failed for %s: %ld", name, error);
			DetourTransactionAbort();
			return false;
		}

		// Attach
		error = DetourAttach(original, hookFunc);
		if (error != NO_ERROR)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] DetourAttach failed for %s: %ld", name, error);
			DetourTransactionAbort();
			return false;
		}

		error = DetourTransactionCommit();
		if (error != NO_ERROR)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] DetourTransactionCommit failed for %s: %ld", name,
			                             error);
			return false;
		}

		te::sdk::helper::logging::Log("[FenixZone AC Bypass] Hooked %s at 0x%p", name, (void*)sig);
		return true;
	}

	bool FindMethodAndHook()
	{
		te::sdk::helper::logging::Log("[FenixZone AC Bypass] Scanning for signatures...");

		//uintptr_t sigTerminateGTA = helper::PatternScan(g_mappedBase, SIG_FENIXZONE_CLOSE, false);
		//uintptr_t sigTimerFunc = helper::PatternScan(g_mappedBase, SIG_FENIXZONE_TIMER_FUNC, false);

		bool success = true;

		//success &= TryCreateHook("TerminateGTA", sigTerminateGTA, &hkTerminateGTA, reinterpret_cast<LPVOID*>(&oTerminateGTA));
		success &= InstallChatPushHook(g_mappedBase);
		//success &= TryCreateHook("TimerFunc", sigTimerFunc, &hkTimerFunc, reinterpret_cast<LPVOID*>(&oTimerFunc));

		if (success)
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] All hooks attached successfully.");
		else
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] One or more hooks failed.");

		return success;
	}

	ManualMapResult ManualMapDllFromMemory(const std::vector<uint8_t>& dllBytes)
	{
		ManualMapResult result;

		if (dllBytes.size() < sizeof(IMAGE_DOS_HEADER)) {
			te::sdk::helper::logging::Log("[ManualMap] Input buffer too small for IMAGE_DOS_HEADER");
			return result;
		}

		if (dllBytes[0] == 'A' && dllBytes[1] == 'X') {
			te::sdk::helper::logging::Log("[ManualMap] Obfuscated AX header detected, converting to MZ");
			const_cast<uint8_t&>(dllBytes[0]) = 'M';
			const_cast<uint8_t&>(dllBytes[1]) = 'Z';
		}

		auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllBytes.data());
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			te::sdk::helper::logging::Log("[ManualMap] Invalid DOS signature (expected MZ)");
			return result;
		}

		auto* ntHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(dllBytes.data() + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
			te::sdk::helper::logging::Log("[ManualMap] Invalid NT signature (expected PE)");
			return result;
		}

		const auto& optional = ntHeader->OptionalHeader;
		SIZE_T sizeOfImage = optional.SizeOfImage;
		SIZE_T sizeOfHeaders = optional.SizeOfHeaders;

		te::sdk::helper::logging::Log("[ManualMap] Mapping image of size 0x%X (headers: 0x%X)", (unsigned)sizeOfImage, (unsigned)sizeOfHeaders);

		LPVOID baseAddress = VirtualAlloc(reinterpret_cast<LPVOID>(optional.ImageBase),
			sizeOfImage,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);

		if (!baseAddress) {
			te::sdk::helper::logging::Log("[ManualMap] Failed to allocate at preferred base 0x%p, trying anywhere", (void*)optional.ImageBase);
			baseAddress = VirtualAlloc(nullptr, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!baseAddress) {
				te::sdk::helper::logging::Log("[ManualMap] VirtualAlloc failed");
				return result;
			}
		}

		te::sdk::helper::logging::Log("[ManualMap] Allocated image at 0x%p", baseAddress);
		result.imageBase = baseAddress;

		std::memcpy(baseAddress, dllBytes.data(), sizeOfHeaders);

		auto* section = IMAGE_FIRST_SECTION(ntHeader);
		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i, ++section)
		{
			void* dest = reinterpret_cast<uint8_t*>(baseAddress) + section->VirtualAddress;
			const void* src = dllBytes.data() + section->PointerToRawData;
			std::memcpy(dest, src, section->SizeOfRawData);
			te::sdk::helper::logging::Log("[ManualMap] Copied section %.*s to 0x%p (size: 0x%X)",
				8, section->Name, dest, section->SizeOfRawData);
		}

		// Resolve imports
		if (optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			auto* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
				reinterpret_cast<uint8_t*>(baseAddress) +
				optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			while (importDesc->Name)
			{
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

				while (thunkRef->u1.AddressOfData)
				{
					FARPROC func = nullptr;
					if (origThunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						func = GetProcAddress(hDll, reinterpret_cast<LPCSTR>(
							origThunkRef->u1.Ordinal & 0xFFFF));
					}
					else
					{
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

		// Relocations
		if (reinterpret_cast<uintptr_t>(baseAddress) != optional.ImageBase &&
			optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			uintptr_t delta = reinterpret_cast<uintptr_t>(baseAddress) - optional.ImageBase;

			auto* reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<uint8_t*>(baseAddress) +
				optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			while (reloc->VirtualAddress)
			{
				DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* relocData = reinterpret_cast<WORD*>(reloc + 1);

				for (DWORD i = 0; i < count; ++i)
				{
					WORD typeOffset = relocData[i];
					WORD type = typeOffset >> 12;
					WORD offset = typeOffset & 0xFFF;

					if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
					{
						uintptr_t* patchAddr = reinterpret_cast<uintptr_t*>(
							reinterpret_cast<uint8_t*>(baseAddress) + reloc->VirtualAddress + offset);
						*patchAddr += delta;
					}
				}

				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
					reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
			}

			te::sdk::helper::logging::Log("[ManualMap] Relocations applied (delta: 0x%p)", (void*)delta);
		}

		// Return entry point
		result.entryPoint = reinterpret_cast<void*>(
			reinterpret_cast<uint8_t*>(baseAddress) + optional.AddressOfEntryPoint);

		te::sdk::helper::logging::Log("[ManualMap] Mapping complete. Entry point at 0x%p", result.entryPoint);
		return result;
	}

	void LogSessionInfo()
	{
		te::sdk::helper::logging::Log("[SessionInfo] === Session Information Dump ===");
		te::sdk::helper::logging::Log("[SessionInfo] Server IP: %s", te::sdk::GetSessionInfo().serverIP);
		te::sdk::helper::logging::Log("[SessionInfo] Server Port: %u", te::sdk::GetSessionInfo().serverPort);
		te::sdk::helper::logging::Log("[SessionInfo] Client Port: %u", te::sdk::GetSessionInfo().clientPort);
		te::sdk::helper::logging::Log("[SessionInfo] Is Connected: %s", te::sdk::GetSessionInfo().isConnected ? "true" : "false");
		te::sdk::helper::logging::Log("[SessionInfo] Depreciated: %u", te::sdk::GetSessionInfo().depreciated);
		te::sdk::helper::logging::Log("[SessionInfo] Thread Sleep Timer: %d ms", te::sdk::GetSessionInfo().threadSleepTimer);
		te::sdk::helper::logging::Log("[SessionInfo] === End Session Information ===");
	}

	std::vector<uint8_t> LoadAnticheatFZ()
	{
		char path[MAX_PATH];
		DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
		if (len == 0 || len == MAX_PATH) {
			std::cerr << "Failed to get module path\n";
			return {};
		}

		std::string basePath(path);
		size_t lastSlash = basePath.find_last_of("\\/");
		if (lastSlash != std::string::npos) {
			basePath = basePath.substr(0, lastSlash + 1);
		}

		std::string filePath = basePath + "rce_protection\\fz_bypass\\anticheat.fz";

		std::ifstream file(filePath, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			std::cerr << "Failed to open: " << filePath << "\n";
			return {};
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<uint8_t> buffer(size);
		if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
			std::cerr << "Failed to read file: " << filePath << "\n";
			return {};
		}

		return buffer;
	}

	std::vector<uint8_t> LoadAnticheatCommFZ()
	{
		char path[MAX_PATH];
		DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
		if (len == 0 || len == MAX_PATH) {
			std::cerr << "Failed to get module path\n";
			return {};
		}

		std::string basePath(path);
		size_t lastSlash = basePath.find_last_of("\\/");
		if (lastSlash != std::string::npos) {
			basePath = basePath.substr(0, lastSlash + 1);
		}

		std::string filePath = basePath + "rce_protection\\fz_bypass\\comm.fz";

		std::ifstream file(filePath, std::ios::binary | std::ios::ate);
		if (!file.is_open()) {
			std::cerr << "Failed to open: " << filePath << "\n";
			return {};
		}

		std::streamsize size = file.tellg();
		file.seekg(0, std::ios::beg);

		std::vector<uint8_t> buffer(size);
		if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
			std::cerr << "Failed to read file: " << filePath << "\n";
			return {};
		}

		return buffer;
	}

	size_t GetFunctionSizeByRetn(uintptr_t funcAddr, size_t maxScanSize = 0x2000)
	{
		auto code = reinterpret_cast<uint8_t*>(funcAddr);

		for (size_t i = 0; i + 3 < maxScanSize; ++i)
		{
			// Look for different return patterns
			if ((code[i] == 0xC2 && i + 2 < maxScanSize) ||  // RET imm16
				(code[i] == 0xC3) ||                          // RET
				(code[i] == 0xCA && i + 2 < maxScanSize) ||   // RETF imm16  
				(code[i] == 0xCB))                            // RETF
			{
				// For RET imm16, add 3 bytes (opcode + 2 byte operand)
				if (code[i] == 0xC2 || code[i] == 0xCA)
					return i + 3;
				else
					return i + 1;
			}
		}

		return maxScanSize; // Return max size if no return found
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

	BOOL SafeCallFunction(uintptr_t funcAddr, uint32_t* result)
	{
		__try {
			uint8_t* targetCode = reinterpret_cast<uint8_t*>(funcAddr);
			*result = *reinterpret_cast<uint32_t*>(targetCode);
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	bool Patch_AllCreateThreadInFunction(uintptr_t funcAddr)
	{
		// Validate memory
		MEMORY_BASIC_INFORMATION mbi;
		if (!VirtualQuery(reinterpret_cast<void*>(funcAddr), &mbi, sizeof(mbi))) {
			sdk::helper::logging::Log("[Bypass] Failed to query memory at 0x%p", (void*)funcAddr);
			return true;
		}

		if (mbi.State != MEM_COMMIT ||
			!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
			sdk::helper::logging::Log("[Bypass] Memory at 0x%p is not executable", (void*)funcAddr);
			return true;
		}

		// FIXED: Increased scan size and simplified logic
		uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		uintptr_t regionEnd = regionStart + mbi.RegionSize;
		uintptr_t maxScanEnd = funcAddr + 0x1000; // Increased to 4KB

		if (maxScanEnd > regionEnd) {
			maxScanEnd = regionEnd;
		}

		size_t funcSize = maxScanEnd - funcAddr;
		if (funcSize < 16) {
			sdk::helper::logging::Log("[Bypass] Function size too small: 0x%X bytes", (unsigned)funcSize);
			return true;
		}

		sdk::helper::logging::Log("[Bypass] Scanning 0x%X bytes at 0x%p", (unsigned)funcSize, (void*)funcAddr);

		auto code = reinterpret_cast<uint8_t*>(funcAddr);
		int patched = 0;

		HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
		if (!hKernel32) {
			sdk::helper::logging::Log("[Bypass] Failed to get kernel32.dll handle");
			return true;
		}

		FARPROC pCreateThread = GetProcAddress(hKernel32, "CreateThread");
		if (!pCreateThread) {
			sdk::helper::logging::Log("[Bypass] Failed to get CreateThread address");
			return true;
		}

		__try {
			// FIXED: Simplified linear scanning without chunking
			for (size_t i = 0; i + 5 <= funcSize; ++i)
			{
				if (code[i] == 0xE8) // CALL instruction
				{
					int32_t rel = *reinterpret_cast<int32_t*>(&code[i + 1]);
					uintptr_t callTarget = funcAddr + i + 5 + rel;

					// Bounds check
					if (callTarget < 0x10000 || callTarget > 0x7FFFFFFF) {
						continue;
					}

					// Check direct call to CreateThread
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

					// Check import thunk call
					uint8_t thunkBytes[6];
					if (SafeReadMemory(reinterpret_cast<void*>(callTarget), thunkBytes, 6))
					{
						if (thunkBytes[0] == 0xFF && thunkBytes[1] == 0x25) // JMP [address]
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
										memset(&code[i], 0x90, 5); // NOP
										VirtualProtect(&code[i], 5, oldProtect, &oldProtect);
										++patched;
									}
								}
							}
						}
					}
				}
				// Check indirect calls: FF 15 [address]
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
									memset(&code[i], 0x90, 6); // NOP
									VirtualProtect(&code[i], 6, oldProtect, &oldProtect);
									++patched;
									i += 5; // Skip the rest of this instruction
								}
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			sdk::helper::logging::Log("[Bypass] Exception during scanning at 0x%p", (void*)funcAddr);
		}

		sdk::helper::logging::Log("[Bypass] Patched %d CreateThread calls", patched);
		return true;
	}

	BOOL SafeCallDllMain(void* entryPoint, void* base)
	{
		typedef BOOL(WINAPI* DllMainFunc)(HINSTANCE, DWORD, LPVOID);
		DllMainFunc DllMain = reinterpret_cast<DllMainFunc>(entryPoint);

		BOOL result = FALSE;

		__try {
			result = DllMain(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, nullptr);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			sdk::helper::logging::Log("[DllMain] Exception occurred during DllMain execution");
			result = FALSE;
		}

		return result;
	}

	std::string CreateCustomSpoofedButoCommand()
	{
		std::string spoofedCommand = "/buto CLA: " +
			GetRandomDisplayDevice() + " " +           // GPU: Random GPU instead of RTX 3060 Ti
			RandomRAM() + " " +                        // RAM: Random RAM instead of 16609312 KB
			std::to_string(4 + rand() % 13) + " " +    // Processors: 4-16 instead of 12
			std::to_string(4 + rand() % 4) + "-" +     // Keyboard type: 4-7 instead of 4
			std::to_string(rand() % 12) + "-" +        // Keyboard subtype: 0-11 instead of 0
			std::to_string(1 + rand() % 12) + "-" +    // Function keys: 1-12 instead of 12
			std::to_string(43 + rand() % 10) + " " +   // System metrics: 43-52 instead of 6
			RandomCPU() + " " +                        // CPU: Random CPU instead of i5-11400F
			GenerateRandomCPUID();                     // CPUID: Random values instead of 0x000A0671 0xBFEBFBFF 0x7FFAFBBF

		return spoofedCommand;
	}

	std::string GenerateDRAString()
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

					te::sdk::helper::logging::Log("[DRA Generator] DRA string: %s", draString.c_str());
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

	std::string CreateSpoofedQuotoCommand()
	{
		std::string spoofedCommand = "/quto MON: " +
			GetRandomDisplayDevice() + " " +           // GPU: Random GPU
			std::to_string(4 + rand() % 13) + " " +    // Processors: 4-16
			std::to_string(4 + rand() % 4) + "-" +     // Keyboard type: 4-7
			std::to_string(rand() % 12) + "-" +        // Keyboard subtype: 0-11
			std::to_string(1 + rand() % 12) + "-" +    // Function keys: 1-12
			std::to_string(43 + rand() % 10) + " " +   // System metrics: 43-52
			RandomCPU() + " " +                        // CPU: Random CPU
			RandomMonitorID() + " " +                  // Monitor ID: AUS278F
			RandomResolution();                        // Resolution: 598X336

		return spoofedCommand;
	}

	std::string CreateSpoofedButoCommandWithDRA()
	{
		std::string spoofedCommand = "/buto DRA: " + GenerateDRAString();
		return spoofedCommand;
	}

	void EmulateCommands()
	{
		if (!g_chatPushHook.isHooked) {
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] Chat hook not installed, cannot emulate commands");
			return;
		}

		// Generate and send custom spoofed /buto command
		std::string claCommand = CreateCustomSpoofedButoCommand();
		HookedChatPush(reinterpret_cast<int>(claCommand.c_str()));

		// Generate and send DRA command
		std::string draCommand = CreateSpoofedButoCommandWithDRA();
		HookedChatPush(reinterpret_cast<int>(draCommand.c_str()));

		// Generate and send MON command
		/*std::string monCommand = CreateSpoofedQuotoCommand();
		HookedChatPush(reinterpret_cast<int>(monCommand.c_str()));*/

		// Send /cuco 8 command at the end
		//std::string cucoCommand = "/cuco 8";
		//HookedChatPush(reinterpret_cast<int>(cucoCommand.c_str()));
	}

	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName)
	{
		// Make a copy of the BitStream to avoid modifying the original read position
		int originalOffset = bs->GetReadOffset();

		// Save the original data for later use
		size_t totalBytes = bs->GetNumberOfBytesUsed();
		std::vector<unsigned char> allData(totalBytes);

		// Reset read position to start
		bs->SetReadOffset(0);

		// Read all data into our buffer
		bs->Read((char*)allData.data(), totalBytes);

		// Restore original read position
		bs->SetReadOffset(originalOffset);

		// Search for MZ header (0x4D, 0x5A)
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

		if (!foundMZ)
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] No MZ header found in BitStream data.");
			return false; // No MZ header found
		}

		// Verify this is potentially a valid PE file
		// Check for "PE\0\0" signature which should be at MZ header + offset 0x3C
		if (mzOffset + 0x40 >= allData.size())
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] Not enough data after MZ header to check for PE signature.");
			return false; // Not enough data for a PE header
		}

		// Read the PE header offset from the MZ header
		uint32_t peOffset = 0;
		if (mzOffset + 0x3C + sizeof(uint32_t) <= allData.size())
		{
			peOffset = *reinterpret_cast<uint32_t*>(&allData[mzOffset + 0x3C]);
		}

		// Check if PE signature is present
		bool isPEFile = false;
		if (mzOffset + peOffset + 4 <= allData.size())
		{
			isPEFile = (allData[mzOffset + peOffset] == 'P' &&
				allData[mzOffset + peOffset + 1] == 'E' &&
				allData[mzOffset + peOffset + 2] == 0 &&
				allData[mzOffset + peOffset + 3] == 0);
		}

		// If we have a valid PE file, save it
		if (isPEFile)
		{
			std::vector<unsigned char> exeData(mzOffset + allData.begin(), allData.end());

			try
			{
				/*void __userpurge Cero(int a1@<ebp>, HWND a2, UINT a3, UINT_PTR a4, DWORD a5)*/
				auto testSig = helper::PatternScan(reinterpret_cast<uint32_t>(exeData.data()), "A1 ? ? ? ? 83 F8 FF", false);
				if (testSig != NULL && g_mappedBase == NULL)
				{
					te::sdk::helper::logging::Log("Detected FenixZone server, preparing bypass ... (rpcId: %i (%s))", rpcId,
						rpcName.c_str());

					auto fzComm = LoadAnticheatCommFZ();
					if (fzComm.empty())
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to load FenixZone Anti Cheat communication module.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x0)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					auto mappedPEComm = ManualMapDllFromMemory(fzComm);
					if (mappedPEComm.imageBase == nullptr || mappedPEComm.entryPoint == nullptr)
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to map FenixZone Anti Cheat communication module.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x1)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					if (!Patch_AllCreateThreadInFunction(reinterpret_cast<uintptr_t>(mappedPEComm.entryPoint)))
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to patch CreateThread in stub function.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x2)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					if (!SafeCallDllMain(mappedPEComm.entryPoint, mappedPEComm.imageBase)) {
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] DllMain call failed or threw an exception.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x3)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					auto fzAnticheat = LoadAnticheatFZ(); 
					if (fzAnticheat.empty())
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to load FenixZone Anti Cheat module.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x4)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					auto mappedPE = ManualMapDllFromMemory(fzAnticheat);
					if (mappedPE.imageBase == nullptr || mappedPE.entryPoint == nullptr)
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to map FenixZone Anti Cheat module.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x5)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					g_mappedBase = reinterpret_cast<uintptr_t>(mappedPE.imageBase);
					g_entryRVA = mappedPE.entryPoint ? (reinterpret_cast<uintptr_t>(mappedPE.entryPoint) - reinterpret_cast<uintptr_t>(mappedPE.imageBase)) : 0;
					g_stubEP = reinterpret_cast<uintptr_t>(mappedPE.entryPoint);

					if (!Patch_AllCreateThreadInFunction(g_stubEP))
					{
						te::sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to patch CreateThread in stub function.");
						te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat. (Error Code: 0x6)", D3DCOLOR_XRGB(255, 0, 0));
						return false;
					}

					te::sdk::helper::logging::Log("Stub DllMain called, bypassing FenixZone Anti Cheat...");

					// Now lets fucking bypass this shit
					{
						if (FindMethodAndHook())
						{
							te::sdk::helper::logging::Log("Methods found and hooked successfully, calling DllMain...");

							if (!SafeCallDllMain(mappedPE.entryPoint, mappedPE.imageBase)) {
								sdk::helper::logging::Log("DllMain call failed or threw an exception");
								return false;
							}

							// Emulate the commands as requested
							EmulateCommands();

							te::sdk::helper::logging::Log("FenixZone Anti Cheat bypassed successfully!");
							te::sdk::helper::samp::AddChatMessage("[#TE] FenixZone Anti Cheat bypassed successfully !", D3DCOLOR_XRGB(128, 235, 52));
						}
						else
						{
							te::sdk::helper::logging::Log("Failed to find and hook methods, aborting bypass.");
							te::sdk::helper::samp::AddChatMessage("[#TE] Failed to bypass FenixZone Anti Cheat.", D3DCOLOR_XRGB(255, 0, 0));
							return false;
						}
					}
				}
				else
				{
					te::sdk::helper::logging::Log("FenixZone server not detected, skipping.");
					LogSessionInfo();
				}
				return true;
			}
			catch (const std::exception& e)
			{
				te::sdk::helper::logging::Log("Exception while processing PE executable: %s", e.what());
			}
		}
		else
		{
			te::sdk::helper::logging::Log("[FenixZone AC Bypass] No valid PE file found in BitStream data (rpcId: %i, rpcName: %s)", rpcId, rpcName.c_str());
		}

		return false;
	}
}
