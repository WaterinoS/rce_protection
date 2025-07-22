#include "te-fz-bypass.h"
#include "te-rce-protection.h"

#include <vector>
#include <string>
#include <array>
#include <regex>

#include "Detours/detours_x86.h"
#pragma comment(lib, "Detours/detours_x86.lib")

namespace te::rce::fz::bypass
{
	// Signatures
	constexpr const char* SIG_FENIXZONE_COMM = "55 89 E5 57 56 53 83 EC 4C 8B 75 08 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? FF 15 ? ? ? ? 89 C3";
	constexpr const char* SIG_FENIXZONE_CLOSE = "55 89 E5 83 EC 18 C7 05 ? ? ? ? ? ? ? ?";
	constexpr const char* SIG_FENIXZONE_CHAT = "55 89 E5 56 53 83 EC 10 E8 ? ? ? ?";
	constexpr const char* SIG_FENIXZONE_CHAT_PUSH = "55 89 E5 53 89 C3 83 EC 14 E8 ? ? ? ?";
	constexpr const char* SIG_FENIXZONE_TIMER = "C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ? E8 ? ? ? ? 83 EC 10 C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 44 24 ? ? ? ? ? C7 04 24 ? ? ? ?";
	constexpr const char* SIG_FENIXZONE_TIMER_FUNC = "55 89 E5 57 56 53 81 EC ? ? ? ? 83 3D ? ? ? ? ?";
	constexpr const char* SIG_FENIXZONE_ENTRY = "C7 04 24 ? ? ? ? E8 ? ? ? ? 56 8B 80 ? ? ? ? C6 40 04 02 E8";

	// Global variables
	uintptr_t g_mappedBase = 0;
	uintptr_t g_entryRVA = 0;
	uintptr_t g_stubEP = 0;
	uintptr_t g_stubScanSize = 0x300;
	BYTE originalPrologue[9];
	BYTE* trampoline = nullptr;
	uintptr_t g_HookAddress = 0;

	// Comm variables
	uintptr_t g_seedAddr = 0;
	uintptr_t g_counterAddr = 0;
	uintptr_t g_byteArrayAddr = 0;

	// Hooks
	tTerminateGTA oTerminateGTA = nullptr;

	// Other
	std::unordered_map<std::string, PatternData> s_patternCache;

	static std::recursive_mutex g_memoryProtectionMutex;
	static std::atomic<bool> g_isProcessingButo{ false };

	static int CallOriginal(int a1)
	{
		int result;
		__asm {
			mov  eax, a1
			call trampoline
			mov  result, eax
		}
		return result;
	}

	bool SafeVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
		std::lock_guard<std::recursive_mutex> lock(g_memoryProtectionMutex);
		return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) != FALSE;
	}

	std::string RandomHex() {
		std::stringstream ss;
		ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (rand() & 0xFFFFFFFF);
		return ss.str();
	}

	std::string RandomMonitorID() {
		static const char* vendors[] = { "AUO", "CMN", "LGD", "SHP", "BOE" };
		int vendorIdx = rand() % 5;
		int code = 1000 + rand() % 9000;
		return vendors[vendorIdx] + std::to_string(code);
	}

	std::string RandomResolution() {
		static const char* resolutions[] = { "1920X1080", "2560X1440", "1366X768", "1600X900", "3440X1440" };
		return resolutions[rand() % 5];
	}

	std::string RandomRAM() {
		int ramMb = (8 + rand() % 24) * 1024;
		return std::to_string(ramMb * 1024) + " KB";
	}

	std::string RandomCPU() {
		static const char* cpus[] = {
			"Intel(R) Core(TM) i9-14900K", "AMD Ryzen 9 5900X",
			"Intel(R) Core(TM) i5-12600H", "AMD Ryzen 7 7840HS"
		};
		return cpus[rand() % 4];
	}

	bool IsSpoofableCommand(const std::string& line) {
		std::regex pattern(R"(\/(buto|quto).*?0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8}.*0x[0-9A-Fa-f]{8})");
		return std::regex_search(line, pattern);
	}

	std::string ReplaceHexWithRandom(const std::string& input) {
		std::smatch match;
		std::regex hexRegex(R"(0x[0-9A-Fa-f]{8})");
		std::string result;
		std::string::const_iterator searchStart(input.cbegin());

		while (std::regex_search(searchStart, input.cend(), match, hexRegex)) {
			result.append(searchStart, match[0].first);
			result.append(RandomHex());
			searchStart = match[0].second;
		}
		result.append(searchStart, input.cend());
		return result;
	}

	std::string SpoofCommandHWData(const std::string& input) {
		try {
			if (!IsSpoofableCommand(input)) {
				return input;
			}

			std::string output = input;

			output = std::regex_replace(output, std::regex(R"(\b\d{7,9} KB\b)"), RandomRAM());
			output = std::regex_replace(output, std::regex(R"((\d+(?:th)? Gen .+? Core\(TM\) .+?H))"), RandomCPU());
			output = std::regex_replace(output, std::regex(R"(\b[A-Z]{3}\d{4}\b)"), RandomMonitorID());
			output = std::regex_replace(output, std::regex(R"(\b\d{3,4}X\d{3,4}\b)"), RandomResolution());

			output = std::regex_replace(
				output,
				std::regex(R"(\b(\d{1,2})(?= \d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}))"),
				std::to_string(8 + rand() % 25)
			);

			output = std::regex_replace(
				output,
				std::regex(R"(\b\d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}\b)"),
				std::to_string(rand() % 10) + "-" +
				std::to_string(rand() % 10) + "-" +
				std::to_string(rand() % 20) + "-" +
				std::to_string(rand() % 20)
			);

			output = ReplaceHexWithRandom(output);

			return output;
		}
		catch (const std::regex_error& e) {
			te_sdk::helper::logging::Log("[REGEX ERROR] %s", e.what());
		}
		catch (const std::exception& e) {
			te_sdk::helper::logging::Log("[EXCEPTION] %s", e.what());
		}
		catch (...) {
			te_sdk::helper::logging::Log("[UNKNOWN ERROR] An unknown error occurred while processing the command.");
		}
		return input;
	}

	int __cdecl MySayImpl(int a1, void* returnAddress)
	{
		char* str = reinterpret_cast<char*>(a1);
		if (!str || IsBadStringPtrA(str, 256))
			return CallOriginal(a1);

		auto spoofedCommand = SpoofCommandHWData(str);

		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Command: %s", spoofedCommand.c_str());

#undef min
		size_t copyLen = std::min(spoofedCommand.length(), size_t(255));
		strncpy(str, spoofedCommand.c_str(), copyLen);
		str[copyLen] = '\0';

		return CallOriginal(a1);
	}

	bool InitButoPointers()
	{
		// 1. dword_6C0CEC00 (seed)
		const char* sigSeed = "A1 ? ? ? ? 05 ? ? ? ? 89 85 ? ? ? ? EB 17";
		uintptr_t matchSeed = te::rce::helper::PatternScan((uint32_t)g_mappedBase, sigSeed, false);
		if (!matchSeed)
		{
			te_sdk::helper::logging::Log("[InitButoPointers] Signature for seed not found.");
			return false;
		}
		g_seedAddr = *(uint32_t*)(matchSeed + 1);
		te_sdk::helper::logging::Log("[InitButoPointers] Found seed: RVA=0x%X -> VA=0x%08X", matchSeed - (uintptr_t)g_mappedBase, g_seedAddr);

		// 2. dword_6C0CF450 (counter)
		const char* sigCounter = "A3 ? ? ? ? 83 F8 02 75 10 FF 05 ? ? ? ? C7 05";
		uintptr_t matchCounter = te::rce::helper::PatternScan((uintptr_t)g_mappedBase, sigCounter, false);
		if (!matchCounter)
		{
			te_sdk::helper::logging::Log("[InitButoPointers] Signature for counter not found.");
			return false;
		}
		g_counterAddr = *(uint32_t*)(matchCounter + 1);
		te_sdk::helper::logging::Log("[InitButoPointers] Found counter: RVA=0x%X -> VA=0x%08X", matchCounter - (uintptr_t)g_mappedBase, g_counterAddr);

		// 3. byte_6C0CA160 (input string)
		const char* sigArray = "B8 ? ? ? ? 8D 4B 01 E8 ? ? ? ? C6 83 ? ? ? ? ? E8 ? ? ? ? 89 74 24 08 C7 44 24 ? ? ? ? ? 89 04 24 E8 ? ? ? ? 83 EC 0C EB 07";
		uintptr_t matchArray = te::rce::helper::PatternScan((uint32_t)g_mappedBase, sigArray, false);
		if (!matchArray)
		{
			te_sdk::helper::logging::Log("[InitButoPointers] Signature for byte array not found.");
			return false;
		}
		g_byteArrayAddr = *(uint32_t*)(matchArray + 1);
		te_sdk::helper::logging::Log("[InitButoPointers] Found byteArray: RVA=0x%X -> VA=0x%08X", matchArray - (uintptr_t)g_mappedBase, g_byteArrayAddr);

		return true;
	}

	__declspec(naked) int MySay()
	{
		__asm {
			push[esp]
			push eax
			call MySayImpl
			add esp, 8
			ret
		}
	}

	void __stdcall hkTerminateGTA(HWND hWnd, UINT msg, UINT_PTR idEvent, DWORD dwTime)
	{
		// EMPTY
	}


	std::string GenerateButoStringFromMappedMemory()
	{
		// Prevent recursive calls that could cause deadlock
		if (g_isProcessingButo.exchange(true)) {
			return "";
		}

		if (g_seedAddr == 0 || g_counterAddr == 0 || g_byteArrayAddr == 0) {
			te_sdk::helper::logging::Log("[GenerateButoStringFromMappedMemory] Invalid pointer(s): seed=0x%X counter=0x%X array=0x%X",
				g_seedAddr, g_counterAddr, g_byteArrayAddr);
			g_isProcessingButo = false;
			return "";
		}

		try {
			uint32_t* pCounter = reinterpret_cast<uint32_t*>(g_counterAddr);
			uint32_t* pSeed = reinterpret_cast<uint32_t*>(g_seedAddr);
			uint8_t* byteArray = reinterpret_cast<uint8_t*>(g_byteArrayAddr);

			uint32_t hFileb = *pSeed + 300;
			uint8_t buffer[0x80] = {};
			int v316 = 0;

			while (byteArray[v316])
				++v316;

			for (int i = 0; i < v316; ++i)
			{
				uint8_t ch = byteArray[i];
				uint32_t tmp = ((hFileb >> 3) + 7) ^ (33 * hFileb);
				uint8_t mixed = (uint8_t)((tmp << 5) | (tmp >> 3));
				uint8_t v30 = mixed ^ ch;
				hFileb = mixed;

				uint8_t v31 = (v30 << 3) | (v30 >> 5);
				uint8_t high = (v31 >> 4) & 0xF;
				uint8_t low = v31 & 0xF;

				size_t len = strlen((char*)buffer);
				if (len > 125) break;

				buffer[len] = (high <= 9) ? (high + '0') : (high + '7');
				buffer[len + 1] = (low <= 9) ? (low + '0') : (low + '7');
				buffer[len + 2] = 0;
			}

			//te_sdk::helper::logging::Log("[BUTO] Before increment: seed=%u counter=%u", *pSeed, *pCounter);

			DWORD oldProt;
			if (SafeVirtualProtect(pCounter, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProt))
			{
				uint32_t counter = ++(*pCounter);
				if (counter == 2)
				{
					SafeVirtualProtect(pSeed, sizeof(uint32_t), PAGE_EXECUTE_READWRITE, &oldProt);
					++(*pSeed);
					SafeVirtualProtect(pSeed, sizeof(uint32_t), oldProt, &oldProt);

					*pCounter = 0;
				}
				SafeVirtualProtect(pCounter, sizeof(uint32_t), oldProt, &oldProt);
			}

			g_isProcessingButo = false;
			return std::string((char*)buffer);
		}
		catch (...) {
			g_isProcessingButo = false;
			return "";
		}
	}

	typedef void(__cdecl* tSub6C0C12A8)(
		struct _WIN32_FIND_DATAA* FirstFileA,
		signed int cFileName,
		struct _FILETIME* p_Buffer,
		HWND a4,
		UINT a5,
		UINT_PTR a6,
		DWORD a7);
	tSub6C0C12A8 oSub6C0C12A8 = nullptr;

	int g_step = 0;

	void __cdecl hkSub6C0C12A8(
		struct _WIN32_FIND_DATAA* FirstFileA,
		signed int cFileName,
		struct _FILETIME* p_Buffer,
		HWND a4,
		UINT a5,
		UINT_PTR a6,
		DWORD a7)
	{
		//te_sdk::helper::logging::Log("[FenixZone AC Bypass] hkSub6C0C12A8 called. Step: %d", g_step);

		if (g_step > 0 && g_step % 15 == 0)
		{
			std::string buto = GenerateButoStringFromMappedMemory();

			char cmd[128];
			snprintf(cmd, sizeof(cmd), "/buto %s", buto.c_str());
			MySayImpl((int)cmd, 0);
		}

		++g_step;
	}

	static PatternData& ParsePattern(const char* sig) {
		auto it = s_patternCache.find(sig);
		if (it != s_patternCache.end()) return it->second;

		PatternData pd;
		const char* cur = sig;
		while (*cur) {
			if (*cur == '?') {
				++cur;
				if (*cur == '?') ++cur;
				pd.bytes.push_back(0);
				pd.mask.push_back(false);
			}
			else {
				pd.bytes.push_back(uint8_t(strtoul(cur, const_cast<char**>(&cur), 16)));
				pd.mask.push_back(true);
			}
			if (*cur == ' ') ++cur;
		}
		pd.firstWildcard = !pd.mask[0];
		pd.firstByte = pd.bytes[0];
		return s_patternCache.emplace(sig, std::move(pd)).first->second;
	}

	uintptr_t PatternScanRCEOnly(const char* signature, bool skipFirst = false) {
		auto& pat = ParsePattern(signature);
		size_t  pLen = pat.bytes.size();
		if (pLen == 0) return 0;

		MEMORY_BASIC_INFORMATION mbi;
		uintptr_t address = 0;
		bool foundOnce = false;

		while (VirtualQuery((void*)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
			if (mbi.State == MEM_COMMIT
				&& mbi.Type == MEM_PRIVATE
				&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				&& !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
			{
				auto* region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
				size_t  regionSize = mbi.RegionSize;
				if (regionSize >= pLen) {
					const uint8_t* cur = region;
					const uint8_t* end = region + regionSize - pLen;

					while (cur <= end) {
						if (!pat.firstWildcard) {
							cur = (const uint8_t*)memchr(cur, pat.firstByte, (end - cur) + 1);
							if (!cur) break;
						}
						bool ok = true;
						for (size_t j = 0; j < pLen; ++j) {
							if (pat.mask[j] && cur[j] != pat.bytes[j]) {
								ok = false;
								break;
							}
						}
						if (ok) {
							if (skipFirst && !foundOnce) {
								foundOnce = true;
							}
							else {
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

	bool HookChatPush()
	{
		g_HookAddress = PatternScanRCEOnly(SIG_FENIXZONE_CHAT_PUSH);
		if (!g_HookAddress) return false;

		constexpr SIZE_T prologueSize = 9;
		memcpy(originalPrologue, (void*)g_HookAddress, prologueSize);

		trampoline = (BYTE*)VirtualAlloc(NULL, prologueSize + 5,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (!trampoline) return false;

		memcpy(trampoline, originalPrologue, prologueSize);

		BYTE* p = trampoline + prologueSize;
		p[0] = 0xE9;
		*reinterpret_cast<DWORD*>(p + 1) =
			(DWORD)((g_HookAddress + prologueSize) - (((uintptr_t)p) + 5));

		DWORD old;
		if (!SafeVirtualProtect((LPVOID)g_HookAddress, 5, PAGE_EXECUTE_READWRITE, &old)) {
			return false;
		}
		{
			BYTE* dst = (BYTE*)g_HookAddress;
			dst[0] = 0xE9; // JMP
			*reinterpret_cast<DWORD*>(dst + 1) =
				(DWORD)((uintptr_t)MySay - (g_HookAddress + 5));
		}
		SafeVirtualProtect((LPVOID)g_HookAddress, 5, old, &old);
		return true;
	}

	bool TryCreateHook(const char* name, uintptr_t sig, LPVOID hookFunc, LPVOID* original)
	{
		if (sig == 0)
		{
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] Signature for %s not found.", name);
			return false;
		}

		LONG error = NO_ERROR;

		// Set the original function pointer (Detours expects the original, NOT the address!)
		*original = reinterpret_cast<LPVOID>(sig);

		error = DetourTransactionBegin();
		if (error != NO_ERROR) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] DetourTransactionBegin failed for %s: %ld", name, error);
			return false;
		}

		error = DetourUpdateThread(GetCurrentThread());
		if (error != NO_ERROR) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] DetourUpdateThread failed for %s: %ld", name, error);
			DetourTransactionAbort();
			return false;
		}

		// Attach
		error = DetourAttach(original, hookFunc);
		if (error != NO_ERROR) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] DetourAttach failed for %s: %ld", name, error);
			DetourTransactionAbort();
			return false;
		}

		error = DetourTransactionCommit();
		if (error != NO_ERROR) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] DetourTransactionCommit failed for %s: %ld", name, error);
			return false;
		}

		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Hooked %s at 0x%p", name, (void*)sig);
		return true;
	}

	bool FindMethodAndHook()
	{
		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Scanning for signatures...");

		uintptr_t sigTerminateGTA = te::rce::helper::PatternScan((uint32_t)g_mappedBase, SIG_FENIXZONE_CLOSE, false);
		uintptr_t sigTimerFunc = te::rce::helper::PatternScan((uint32_t)g_mappedBase, SIG_FENIXZONE_TIMER_FUNC, false);

		bool success = true;

		success &= TryCreateHook("TerminateGTA", sigTerminateGTA, &hkTerminateGTA, reinterpret_cast<LPVOID*>(&oTerminateGTA));
		success &= HookChatPush();
		success &= TryCreateHook("TimerFunc", sigTimerFunc, &hkSub6C0C12A8, reinterpret_cast<LPVOID*>(&oSub6C0C12A8));

		if (success)
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] All hooks attached successfully.");
		else
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] One or more hooks failed.");

		return success;
	}

	void* ManualMapPE_NoEntry(std::vector<unsigned char> exeData)
	{
		if (exeData.size() < sizeof(IMAGE_DOS_HEADER))
			return nullptr;

		auto* dosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(exeData.data());
		if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		auto* ntHdr = reinterpret_cast<PIMAGE_NT_HEADERS>(exeData.data() + dosHdr->e_lfanew);
		if (ntHdr->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		SIZE_T imageSize = ntHdr->OptionalHeader.SizeOfImage;

		BYTE* mapped = (BYTE*)VirtualAlloc(nullptr,
			imageSize,
			MEM_COMMIT | MEM_RESERVE,
			PAGE_EXECUTE_READWRITE);
		if (!mapped) return nullptr;

		SIZE_T headersSize = ntHdr->OptionalHeader.SizeOfHeaders;
		memcpy(mapped, exeData.data(), headersSize);

		auto* section = IMAGE_FIRST_SECTION(ntHdr);
		for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; ++i, ++section)
		{
			if (section->SizeOfRawData == 0) continue;
			BYTE* dest = mapped + section->VirtualAddress;
			const BYTE* src = exeData.data() + section->PointerToRawData;
			memcpy(dest, src, section->SizeOfRawData);
		}

		ULONG_PTR delta = (ULONG_PTR)mapped - ntHdr->OptionalHeader.ImageBase;
		if (delta != 0 && ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		{
			auto* relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
				mapped +
				ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

			SIZE_T relocSize = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
			SIZE_T parsed = 0;

			while (parsed < relocSize && relocDir->SizeOfBlock)
			{
				DWORD count = (relocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto* entry = reinterpret_cast<WORD*>(relocDir + 1);
				for (DWORD j = 0; j < count; ++j, ++entry)
				{
					WORD type = *entry >> 12;
					WORD offset = *entry & 0x0FFF;
					if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64)
					{
						ULONG_PTR* patchAddr = reinterpret_cast<ULONG_PTR*>(
							mapped + relocDir->VirtualAddress + offset);
						*patchAddr = *patchAddr + delta;
					}
				}
				parsed += relocDir->SizeOfBlock;
				relocDir = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<BYTE*>(relocDir) + relocDir->SizeOfBlock);
			}
		}

		auto& impDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (impDir.Size)
		{
			auto* importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
				mapped + impDir.VirtualAddress);
			for (; importDesc->Name; ++importDesc)
			{
				char* dllName = reinterpret_cast<char*>(mapped + importDesc->Name);
				HMODULE hDll = LoadLibraryA(dllName);
				if (!hDll) continue;

				auto* origFirst = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDesc->OriginalFirstThunk);
				auto* first = reinterpret_cast<PIMAGE_THUNK_DATA>(mapped + importDesc->FirstThunk);

				for (; origFirst->u1.AddressOfData; ++origFirst, ++first)
				{
					FARPROC proc = nullptr;
					if (origFirst->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					{
						proc = GetProcAddress(hDll, MAKEINTRESOURCEA(origFirst->u1.Ordinal & 0xFFFF));
					}
					else
					{
						auto* importByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(
							mapped + origFirst->u1.AddressOfData);
						proc = GetProcAddress(hDll, importByName->Name);
					}
					first->u1.Function = reinterpret_cast<ULONG_PTR>(proc);
				}
			}
		}

		g_mappedBase = (uintptr_t)mapped;
		auto* dos = (PIMAGE_DOS_HEADER)mapped;
		auto* nt = (PIMAGE_NT_HEADERS)(mapped + dos->e_lfanew);
		g_entryRVA = nt->OptionalHeader.AddressOfEntryPoint;
		return mapped;
	}

	void PatchMpressStub()
	{
		if (!g_mappedBase) return;

		if (!g_stubEP)
		{
			auto* dos = (PIMAGE_DOS_HEADER)g_mappedBase;
			auto* nt = (PIMAGE_NT_HEADERS)(g_mappedBase + dos->e_lfanew);
			g_stubEP = (uintptr_t)g_mappedBase + nt->OptionalHeader.AddressOfEntryPoint;
		}

		DWORD oldProt;
		if (!SafeVirtualProtect((void*)g_stubEP, g_stubScanSize, PAGE_EXECUTE_READWRITE, &oldProt)) {
			return;
		}

		BYTE* p = (BYTE*)g_stubEP;

		uintptr_t realDllMainAddr = (uintptr_t)g_mappedBase + g_entryRVA;
		for (size_t i = 0; i + 5 <= g_stubScanSize; ++i)
		{
			if (p[i] == 0xE8)
			{
				int32_t rel = *reinterpret_cast<int32_t*>(p + i + 1);
				uintptr_t target = (uintptr_t)(p + i + 5) + rel;
				if (target == realDllMainAddr)
				{
					p[i + 0] = 0xC3; // RET
					p[i + 1] = 0x90; // NOP
					p[i + 2] = 0x90;
					p[i + 3] = 0x90;
					p[i + 4] = 0x90;
					break;
				}
			}
		}

		for (size_t i = 0; i + 5 <= g_stubScanSize; ++i)
		{
			if (p[i] == 0xE9)
			{
				int32_t rel = *reinterpret_cast<int32_t*>(p + i + 1);
				uintptr_t target = (uintptr_t)(p + i + 5) + rel;
				if (target == realDllMainAddr)
				{
					p[i + 0] = 0xC3;
					p[i + 1] = 0x90;
					p[i + 2] = 0x90;
					p[i + 3] = 0x90;
					p[i + 4] = 0x90;
					break;
				}
			}
		}

		SafeVirtualProtect((void*)g_stubEP, g_stubScanSize, oldProt, &oldProt);
	}

	void CallACRealDllMain()
	{
		if (!g_mappedBase || g_entryRVA == 0) return;
		using DllMainT = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
		auto fn = (DllMainT)(g_mappedBase + g_entryRVA);
		fn((HINSTANCE)g_mappedBase, DLL_PROCESS_ATTACH, nullptr);
	}

	void SimulateVirtualProtectPatch()
	{
		BYTE* addr = reinterpret_cast<BYTE*>(0x6E2E50);
		DWORD oldProtect;

		if (!SafeVirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] Failed VirtualProtect on 0x6E2E50.");
			return;
		}

		*(WORD*)&addr[0] = 0x1CC2;
		addr[2] = 0x00;

		DWORD dummy;
		SafeVirtualProtect(addr, 3, oldProtect, &dummy);

		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Simulated VirtualProtect patch at 0x6E2E50.");
	}

	uintptr_t Get_CreateThreadFunction()
	{
		const char* sigCall = "E8 ? ? ? ? 83 EC 0C C9";
		uintptr_t match = te::rce::helper::PatternScan((uint32_t)g_mappedBase, sigCall, false);
		if (!match) {
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to find call to CreateThread function.");
			return 0;
		}

		int32_t relOffset = *reinterpret_cast<int32_t*>(match + 1);
		uintptr_t targetAddr = match + 5 + relOffset;

		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Found CreateThread initializer function at: 0x%08X", targetAddr);
		return targetAddr;
	}

	struct ThreadSig {
		const char* name;
		const char* pattern;
		bool ripRelative;
		uintptr_t resolvedAddress = 0;
	};

	std::vector<ThreadSig> g_threadSigs;

	void PrepareThreadSigs()
	{
		g_threadSigs.clear();

		g_threadSigs.push_back({
			"sub_6C0C5630",
			"55 89 E5 83 EC 08 E8 ? ? ? ?",
			true
			});

		g_threadSigs.push_back({
			"sub_6C0C7868",
			"55 89 E5 53 31 DB 83 EC 24 E8 ? ? ? ? 8D 55 F4 C7 45 ? ? ? ? ? 89 54 24 04 89 04 24 E8 ? ? ? ? 51",
			false
			});

		g_threadSigs.push_back({
			"sub_6C0C55E0",
			"55 89 E5 53 31 DB 83 EC 24 E8 ? ? ? ? 8D 55 F4 C7 45 ? ? ? ? ? 89 54 24 04 89 04 24 E8 ? ? ? ? 52",
			false
			});

		g_threadSigs.push_back({
			"sub_6C0C8140",
			"55 89 E5 83 EC 28 E8 ? ? ? ?",
			false
			});

		g_threadSigs.push_back({
			"sub_6C0C5644",
			"55 89 E5 57 56 53 81 EC ? ? ? ? C7 04 24 ? ? ? ? E8 ? ? ? ? 89 85 ? ? ? ?",
			false
			});

		for (auto& sig : g_threadSigs)
		{
			uintptr_t match = te::rce::helper::PatternScan((uintptr_t)g_mappedBase, sig.pattern, sig.ripRelative);
			if (match)
			{
				sig.resolvedAddress = match;
				te_sdk::helper::logging::Log("[ThreadSigs] Found %s at 0x%08X", sig.name, match);
			}
			else
			{
				te_sdk::helper::logging::Log("[ThreadSigs] Signature not found: %s", sig.name);
			}
		}
	}

	size_t GetFunctionSizeByRetn(uintptr_t funcAddr, size_t maxScanSize = 0x1000)
	{
		uint8_t* code = reinterpret_cast<uint8_t*>(funcAddr);

		for (size_t i = 0; i + 2 < maxScanSize; ++i)
		{
			if (code[i] == 0xC2 && code[i + 1] == 0x0C && code[i + 2] == 0x00)
			{
				return i + 3;
			}
		}

		return 0;
	}

	void Patch_CreateThread_ByStartAddress(uintptr_t funcAddr, uintptr_t targetStartAddress)
	{
		size_t funcSize = GetFunctionSizeByRetn(funcAddr);
		if (!funcSize)
		{
			te_sdk::helper::logging::Log("[FenixZone AC Bypass] Failed to determine function size.");
			return;
		}

		uint8_t* code = reinterpret_cast<uint8_t*>(funcAddr);
		int patched = 0;

		for (size_t i = 0; i + 40 < funcSize; ++i)
		{
			if (code[i + 0] == 0xC7 &&
				code[i + 1] == 0x44 &&
				code[i + 2] == 0x24 &&
				code[i + 3] == 0x08)
			{
				uint32_t paramAddr = *reinterpret_cast<uint32_t*>(&code[i + 4]);
				//te_sdk::helper::logging::Log("[Debug] Found mov [esp+08], 0x%08X", paramAddr);

				for (size_t k = 4; k <= 40; ++k)
				{
					if (code[i + k] == 0xE8)
					{
						int32_t rel = *reinterpret_cast<int32_t*>(&code[i + k + 1]);
						uintptr_t callTarget = reinterpret_cast<uintptr_t>(&code[i + k + 5]) + rel;

						//te_sdk::helper::logging::Log("[Debug] Found call to 0x%08X", callTarget);

						if (paramAddr == targetStartAddress)
						{
							DWORD oldProtect;
							if (SafeVirtualProtect(&code[i + k], 5, PAGE_EXECUTE_READWRITE, &oldProtect))
							{
								memset(&code[i + k], 0x90, 5);
								SafeVirtualProtect(&code[i + k], 5, oldProtect, &oldProtect);

								//te_sdk::helper::logging::Log("[Patch] NOPed CreateThread call with StartAddress 0x%08X", targetStartAddress);
								++patched;
							}
						}

						break;
					}
				}
			}
		}

		//te_sdk::helper::logging::Log("[FenixZone AC Bypass] Patched %d CreateThread call(s) by StartAddress.", patched);
	}

	void Init_CreateThreadPatch()
	{
		uintptr_t funcAddr = Get_CreateThreadFunction();
		if (!funcAddr) return;

		PrepareThreadSigs();

		for (auto& sig : g_threadSigs)
		{
			if (sig.resolvedAddress == 0) continue;

			Patch_CreateThread_ByStartAddress((uintptr_t)funcAddr, sig.resolvedAddress);
		}

		te_sdk::helper::logging::Log("[FenixZone AC Bypass] Patch CreateThread done.");
	}

	// Function to scan BitStream for MZ header and save PE executables
	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName) {
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

		for (size_t i = 0; i < allData.size() - 1; i++) {
			if (allData[i] == 0x4D && allData[i + 1] == 0x5A) {
				foundMZ = true;
				mzOffset = i;
				break;
			}
		}

		if (!foundMZ) {
			return false; // No MZ header found
		}

		// Verify this is potentially a valid PE file
		// Check for "PE\0\0" signature which should be at MZ header + offset 0x3C
		if (mzOffset + 0x40 >= allData.size()) {
			return false; // Not enough data for a PE header
		}

		// Read the PE header offset from the MZ header
		uint32_t peOffset = 0;
		if (mzOffset + 0x3C + sizeof(uint32_t) <= allData.size()) {
			peOffset = *reinterpret_cast<uint32_t*>(&allData[mzOffset + 0x3C]);
		}

		// Check if PE signature is present
		bool isPEFile = false;
		if (mzOffset + peOffset + 4 <= allData.size()) {
			isPEFile = (allData[mzOffset + peOffset] == 'P' &&
				allData[mzOffset + peOffset + 1] == 'E' &&
				allData[mzOffset + peOffset + 2] == 0 &&
				allData[mzOffset + peOffset + 3] == 0);
		}

		// If we have a valid PE file, save it
		if (isPEFile) {
			// Extract relevant PE header information for logging
			std::string fileType;
			uint16_t machine = 0;
			uint16_t characteristics = 0;
			uint32_t timestamp = 0;

			if (mzOffset + peOffset + 24 <= allData.size()) {
				machine = *reinterpret_cast<uint16_t*>(&allData[mzOffset + peOffset + 4]);
				timestamp = *reinterpret_cast<uint32_t*>(&allData[mzOffset + peOffset + 8]);
				characteristics = *reinterpret_cast<uint16_t*>(&allData[mzOffset + peOffset + 22]);
			}

			// Determine file type based on characteristics
			if (characteristics & 0x2000) {
				fileType = "dll";
			}
			else if (characteristics & 0x0002) {
				fileType = "exe";
			}
			else {
				fileType = "bin";
			}

			// Extract the executable starting from the MZ header
			size_t exeSize = allData.size() - mzOffset;
			std::vector<unsigned char> exeData(mzOffset + allData.begin(), allData.end());

			try {
				auto testSig = te::rce::helper::PatternScan(reinterpret_cast<uint32_t>(exeData.data()), "8B FE 66 AD C1 E0 0C 8B C8 50 AD 2B C8 03 F1 8B C8 57", false);
				if (testSig != NULL && g_mappedBase == NULL)
				{
					te_sdk::helper::logging::Log("Detected FenixZone Anti Cheat signature in PE executable (rpcId: %i (%s))", rpcId, rpcName.c_str());

					ManualMapPE_NoEntry(exeData);

					te_sdk::helper::logging::Log("PE executable mapped successfully, base address: 0x%p", g_mappedBase);
					te_sdk::helper::logging::Log("Patching Mpress stub...");

					PatchMpressStub();

					te_sdk::helper::logging::Log("Mpress stub patched, calling original DllMain...");

					reinterpret_cast<void(*)()>(g_stubEP)();

					te_sdk::helper::logging::Log("Original DllMain called, bypassing FenixZone Anti Cheat...");

					// Now lets fucking bypass this shit
					{
						if (FindMethodAndHook() && InitButoPointers())
						{
							Init_CreateThreadPatch();
							SimulateVirtualProtectPatch();

							CallACRealDllMain();

							te_sdk::helper::logging::Log("FenixZone Anti Cheat bypassed successfully!");
						}
					}
				}

				return true;
			}
			catch (const std::exception& e) {
				te_sdk::helper::logging::Log("Exception while processing PE executable: %s", e.what());
			}
		}

		return false;
	}
}