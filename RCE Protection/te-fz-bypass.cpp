#define NOMINMAX

#include "te-fz-bypass.h"
#include "te-rce-protection.h"

#include <d3d9.h>
#include <vector>
#include <string>
#include <fstream>
#include <regex>
#include <sstream>
#include <iomanip>
#include <unordered_set>
#include <unordered_map>
#include <psapi.h>
#include <TlHelp32.h>

#include <MinHook.h>

#include <winternl.h>
#include <intrin.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

// Extended PROCESSINFOCLASS values not in winternl.h
#define TE_ProcessDebugObjectHandle  ((PROCESSINFOCLASS)30)
#define TE_ProcessDebugFlags         ((PROCESSINFOCLASS)31)

namespace te::rce::fz::bypass
{
	// ---------- Anti-Detection System ----------
	struct HookedFunction {
		std::vector<uint8_t> originalBytes;
		std::string functionName;
		LPVOID pTarget;
		LPVOID pTrampoline;
		bool isActive;
	};

	static std::vector<HookedFunction> g_hookedFunctions;
	static std::unordered_set<uintptr_t> g_protectedRegions;
	static std::unordered_map<std::string, HMODULE> g_hiddenModules;
	static std::recursive_mutex g_antiDetectionMutex;
	static bool g_hooksInitialized = false;
	static bool g_minhookInitialized = false;

	// Thread-local recursion guards
	thread_local bool g_inVirtualQuery = false;
	thread_local bool g_inReadProcessMemory = false;
	thread_local bool g_inGetModuleFileName = false;
	thread_local bool g_inModule32 = false;

	// Memory region tracking for clean reads
	struct MemoryRegion {
		uintptr_t start;
		uintptr_t end;
		std::vector<uint8_t> originalData;
		DWORD originalProtect;
	};
	static std::vector<MemoryRegion> g_memoryRegions;

	// Trampoline pointers (originals after hooking)
	static decltype(&VirtualQuery)         o_VirtualQuery = nullptr;
	static decltype(&VirtualQueryEx)       o_VirtualQueryEx = nullptr;
	static decltype(&ReadProcessMemory)    o_ReadProcessMemory = nullptr;
	static decltype(&FindFirstFileA)       o_FindFirstFileA = nullptr;
	static decltype(&FindNextFileA)        o_FindNextFileA = nullptr;
	static decltype(&EnumProcessModules)   o_EnumProcessModules = nullptr;
	static decltype(&GetModuleFileNameA)   o_GetModuleFileNameA = nullptr;
	static decltype(&GetModuleFileNameW)   o_GetModuleFileNameW = nullptr;
	static decltype(&GetFileAttributesA)   o_GetFileAttributesA = nullptr;
	static decltype(&GetFileAttributesW)   o_GetFileAttributesW = nullptr;
	static decltype(&Module32FirstW)       o_Module32FirstW = nullptr;
	static decltype(&Module32NextW)        o_Module32NextW = nullptr;
	static decltype(&VirtualProtect)       o_VirtualProtect = nullptr;

	// NT function typedefs
	typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

	typedef enum _MEMORY_INFORMATION_CLASS {
		MemoryBasicInformation = 0
	} MEMORY_INFORMATION_CLASS;

	typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T);

	static NtQueryVirtualMemory_t      o_NtQueryVirtualMemory = nullptr;
	static NtReadVirtualMemory_t       o_NtReadVirtualMemory = nullptr;
	static NtQueryInformationProcess_t o_NtQueryInformationProcess = nullptr;

	// ---------- FenixZone Identification ----------

	// Searches raw PE data for a byte sequence (case-insensitive for ASCII)
	static bool FindBytesInData(const std::vector<unsigned char>& data, const char* needle, size_t needleLen) {
		if (needleLen == 0 || data.size() < needleLen) return false;
		auto needleBytes = reinterpret_cast<const unsigned char*>(needle);
		for (size_t i = 0; i <= data.size() - needleLen; i++) {
			bool match = true;
			for (size_t j = 0; j < needleLen; j++) {
				if (data[i + j] != needleBytes[j]) {
					match = false;
					break;
				}
			}
			if (match) return true;
		}
		return false;
	}

	static bool FindStringInData(const std::vector<unsigned char>& data, const char* str) {
		return FindBytesInData(data, str, strlen(str));
	}

	// Identifies if a PE payload is FenixZone anti-cheat based on unique markers
	// Returns confidence score (0-100). >= 30 is considered FenixZone.
	static int IdentifyFenixZone(const std::vector<unsigned char>& peData)
	{
		int score = 0;

		// --- Tier 1: Highly unique FZ strings (20 pts each) ---
		// Spanish-language export/function names unique to FZ
		if (FindStringInData(peData, "esIPdeDigitalOcean"))          score += 20;
		if (FindStringInData(peData, "esServidorDigitalOcean"))      score += 20;
		if (FindStringInData(peData, "obtenerFileSize"))             score += 20;
		if (FindStringInData(peData, "ExisteArchivo"))               score += 20;
		if (FindStringInData(peData, "GetCurrentDirectoryCustom"))   score += 20;
		if (FindStringInData(peData, "MiFuncion"))                   score += 20;
		if (FindStringInData(peData, "descarga-discord"))            score += 20;

		// --- Tier 2: FZ-specific exports/patterns (15 pts each) ---
		if (FindStringInData(peData, "DownloadFileThread"))          score += 15;
		if (FindStringInData(peData, "FastSkin"))                    score += 15;
		if (FindStringInData(peData, "Patinaje"))                    score += 15;
		if (FindStringInData(peData, "FTP_IP"))                      score += 15;
		if (FindStringInData(peData, "FTP_USER"))                    score += 15;
		if (FindStringInData(peData, "FTP_PASSWORD"))                score += 15;
		if (FindStringInData(peData, "OFFSETSSADDCOMMAND"))          score += 15;

		// --- Tier 3: Semi-unique strings (10 pts each) ---
		if (FindStringInData(peData, "WriteMemory"))                 score += 10;
		if (FindStringInData(peData, "SendCommand"))                 score += 10;
		if (FindStringInData(peData, "samp_base"))                   score += 10;
		if (FindStringInData(peData, "ipList"))                      score += 10;
		if (FindStringInData(peData, "asi-s1"))                      score += 10;
		if (FindStringInData(peData, "My Downloader"))               score += 10;
		if (FindStringInData(peData, "Dll1.dll"))                    score += 10;

		// --- Tier 4: Known C2/FTP infrastructure (10 pts each) ---
		if (FindStringInData(peData, "159.223.98.10"))               score += 10;
		if (FindStringInData(peData, "192.95.30.92"))                score += 10;
		if (FindStringInData(peData, "24.152.36.102"))               score += 10;
		if (FindStringInData(peData, "gta:puta@"))                   score += 10;

		// --- Tier 5: Payload filenames (5 pts each) ---
		if (FindStringInData(peData, "az-v2.dll"))                   score += 5;
		if (FindStringInData(peData, "ac-v2.dll"))                   score += 5;
		if (FindStringInData(peData, "nz.dll"))                      score += 5;
		if (FindStringInData(peData, "cn2.dll"))                     score += 5;
		if (FindStringInData(peData, "anti-key.asi"))                score += 5;
		if (FindStringInData(peData, "anti-crashermx.asi"))          score += 5;
		if (FindStringInData(peData, "Anticheat%d.tmp"))             score += 5;

		// --- Tier 6: GCC/MinGW prologue check (5 pts) ---
		// FZ is always compiled with GCC (55 89 E5 pattern)
		uint8_t gccPrologue[] = { 0x55, 0x89, 0xE5 };
		if (FindBytesInData(peData, reinterpret_cast<const char*>(gccPrologue), 3)) score += 5;

		// --- Tier 7: Old known signatures (5 pts each) ---
		// SIG_FENIXZONE_TIMER_FUNC
		uint8_t sigTimer[] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x81, 0xEC };
		if (FindBytesInData(peData, reinterpret_cast<const char*>(sigTimer), 8)) score += 5;
		// SIG_FENIXZONE_CHAT_PUSH
		uint8_t sigChat[] = { 0x55, 0x89, 0xE5, 0x53, 0x89, 0xC3, 0x83, 0xEC, 0x14, 0xE8 };
		if (FindBytesInData(peData, reinterpret_cast<const char*>(sigChat), 10)) score += 5;

		// Obfuscated section name ".Jz?" (very unique)
		if (FindStringInData(peData, ".Jz?"))                        score += 10;

		// Animation strings used by FZ cheats
		if (FindStringInData(peData, "skate_run"))                   score += 5;
		if (FindStringInData(peData, "skate_sprint"))                score += 5;

		return score;
	}

	// ---------- Helper Functions ----------

	extern "C" BOOL __stdcall SafeMemoryCopy_Internal(void* dest, const void* src, size_t size) {
		if (!dest || !src || size == 0) return FALSE;
		__try {
			memcpy(dest, src, size);
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	static bool HasSuspiciousExtension(const std::string& filename) {
		size_t dotPos = filename.find_last_of('.');
		if (dotPos == std::string::npos || dotPos == filename.length() - 1) return false;

		std::string ext = filename.substr(dotPos);
		static const std::vector<std::string> hiddenExtensions = {
			".asi", ".cs", ".sf", ".dll", ".exe", ".lua", ".ifp", ".ws"
		};
		for (const auto& hiddenExt : hiddenExtensions) {
			if (ext == hiddenExt) return true;
		}
		return false;
	}

	static bool IsAddressInSuspiciousModule(LPCVOID lpAddress) {
		HMODULE hModule = NULL;
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(lpAddress), &hModule)) {
			return false;
		}

		char modulePath[MAX_PATH] = { 0 };
		if (!GetModuleFileNameA(hModule, modulePath, MAX_PATH)) return false;

		std::string modPath(modulePath);
		std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);
		size_t lastSlash = modPath.find_last_of("\\/");
		std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;
		return HasSuspiciousExtension(modName);
	}

	static bool ShouldHideModule(HMODULE hModule) {
		char modulePath[MAX_PATH] = { 0 };
		auto hKernel32 = ::GetModuleHandleA("kernel32.dll");
		auto pGetModuleFileNameA = reinterpret_cast<decltype(&GetModuleFileNameA)>(
			::GetProcAddress(hKernel32, "GetModuleFileNameA"));
		if (!pGetModuleFileNameA) return false;
		if (!pGetModuleFileNameA(hModule, modulePath, MAX_PATH)) return false;

		std::string modPath(modulePath);
		std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);
		size_t lastSlash = modPath.find_last_of("\\/");
		std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;

		if (HasSuspiciousExtension(modName)) return true;
		for (const auto& [hiddenName, hiddenModule] : g_hiddenModules) {
			if (hModule == hiddenModule) return true;
		}
		return false;
	}

	// ---------- SEH Helpers ----------

	extern "C" BOOL __stdcall CheckMemoryRegions_SEH(
		uintptr_t addr, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead,
		const std::vector<HookedFunction>* pHooks, const std::vector<MemoryRegion>* pRegions)
	{
		__try {
			size_t maxHooks = std::min(pHooks->size(), size_t(10));
			for (size_t i = maxHooks; i > 0; --i) {
				const auto& hook = (*pHooks)[i - 1];
				if (!hook.isActive) continue;

				uintptr_t hookAddr = reinterpret_cast<uintptr_t>(hook.pTarget);
				uintptr_t hookEnd = hookAddr + hook.originalBytes.size();

				if (addr >= hookAddr && addr < hookEnd) {
					size_t offset = addr - hookAddr;
					size_t copySize = std::min(static_cast<size_t>(nSize), hook.originalBytes.size() - offset);
					memcpy(lpBuffer, hook.originalBytes.data() + offset, copySize);
					if (lpNumberOfBytesRead) *lpNumberOfBytesRead = copySize;
					return TRUE;
				}
			}

			size_t maxRegions = std::min(pRegions->size(), size_t(10));
			for (size_t i = maxRegions; i > 0; --i) {
				const auto& region = (*pRegions)[i - 1];
				if (addr >= region.start && addr < region.end) {
					size_t offset = addr - region.start;
					size_t copySize = std::min(static_cast<size_t>(nSize), region.originalData.size() - offset);
					memcpy(lpBuffer, region.originalData.data() + offset, copySize);
					if (lpNumberOfBytesRead) *lpNumberOfBytesRead = copySize;
					return TRUE;
				}
			}
			return FALSE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return -1;
		}
	}

	// ---------- Hook Implementations ----------

	SIZE_T WINAPI Hooked_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		if (!o_VirtualQuery) return 0;
		if (g_inVirtualQuery) return o_VirtualQuery(lpAddress, lpBuffer, dwLength);

		bool isSuspicious = IsAddressInSuspiciousModule(lpAddress);
		g_inVirtualQuery = true;
		SIZE_T result = o_VirtualQuery(lpAddress, lpBuffer, dwLength);

		if (isSuspicious) {
			g_inVirtualQuery = false;
			SetLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}

		if (result && lpBuffer && !g_memoryRegions.empty()) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);
			size_t maxCheck = std::min(g_memoryRegions.size(), size_t(10));
			for (size_t i = maxCheck; i > 0; --i) {
				const auto& region = g_memoryRegions[i - 1];
				if (addr >= region.start && addr < region.end) {
					lpBuffer->Protect = region.originalProtect;
					lpBuffer->State = MEM_COMMIT;
					lpBuffer->Type = MEM_IMAGE;
					lpBuffer->AllocationProtect = region.originalProtect;
					break;
				}
			}
		}

		g_inVirtualQuery = false;
		return result;
	}

	SIZE_T WINAPI Hooked_VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress,
		PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		if (!o_VirtualQueryEx) return 0;
		if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1)
			return o_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
		if (g_inVirtualQuery)
			return o_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);

		bool isSuspicious = IsAddressInSuspiciousModule(lpAddress);
		g_inVirtualQuery = true;
		SIZE_T result = o_VirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);

		if (isSuspicious) {
			g_inVirtualQuery = false;
			SetLastError(ERROR_INVALID_PARAMETER);
			return 0;
		}

		if (result && lpBuffer && !g_memoryRegions.empty()) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);
			size_t maxCheck = std::min(g_memoryRegions.size(), size_t(10));
			for (size_t i = maxCheck; i > 0; --i) {
				const auto& region = g_memoryRegions[i - 1];
				if (addr >= region.start && addr < region.end) {
					lpBuffer->Protect = region.originalProtect;
					lpBuffer->State = MEM_COMMIT;
					lpBuffer->Type = MEM_IMAGE;
					lpBuffer->AllocationProtect = region.originalProtect;
					break;
				}
			}
		}

		g_inVirtualQuery = false;
		return result;
	}

	NTSTATUS NTAPI Hooked_NtQueryVirtualMemory(
		HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass,
		PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
	{
		if (!o_NtQueryVirtualMemory) return STATUS_NOT_IMPLEMENTED;
		if ((ProcessHandle != GetCurrentProcess() && ProcessHandle != (HANDLE)-1) ||
			MemoryInformationClass != MemoryBasicInformation)
			return o_NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
				MemoryInformation, MemoryInformationLength, ReturnLength);
		if (g_inVirtualQuery)
			return o_NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
				MemoryInformation, MemoryInformationLength, ReturnLength);

		bool isSuspicious = IsAddressInSuspiciousModule(BaseAddress);
		g_inVirtualQuery = true;
		NTSTATUS status = o_NtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass,
			MemoryInformation, MemoryInformationLength, ReturnLength);

		if (isSuspicious) { g_inVirtualQuery = false; return STATUS_ACCESS_DENIED; }

		if (status == STATUS_SUCCESS && MemoryInformation &&
			MemoryInformationLength >= sizeof(MEMORY_BASIC_INFORMATION) && !g_memoryRegions.empty()) {
			auto lpBuffer = reinterpret_cast<PMEMORY_BASIC_INFORMATION>(MemoryInformation);
			uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);
			size_t maxCheck = std::min(g_memoryRegions.size(), size_t(10));
			for (size_t i = maxCheck; i > 0; --i) {
				const auto& region = g_memoryRegions[i - 1];
				if (addr >= region.start && addr < region.end) {
					lpBuffer->Protect = region.originalProtect;
					lpBuffer->State = MEM_COMMIT;
					lpBuffer->Type = MEM_IMAGE;
					lpBuffer->AllocationProtect = region.originalProtect;
					break;
				}
			}
		}

		g_inVirtualQuery = false;
		return status;
	}

	BOOL WINAPI Hooked_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
		LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		if (!o_ReadProcessMemory) return FALSE;
		if (g_inReadProcessMemory)
			return o_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1)
			return o_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);

		g_inReadProcessMemory = true;

		if (g_hookedFunctions.empty() && g_memoryRegions.empty()) {
			BOOL result = o_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
			g_inReadProcessMemory = false;
			return result;
		}

		uintptr_t addr = reinterpret_cast<uintptr_t>(lpBaseAddress);
		std::unique_lock<std::recursive_mutex> lock(g_antiDetectionMutex, std::try_to_lock);
		if (!lock.owns_lock()) {
			BOOL result = o_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
			g_inReadProcessMemory = false;
			return result;
		}

		BOOL regionResult = CheckMemoryRegions_SEH(addr, lpBuffer, nSize, lpNumberOfBytesRead,
			&g_hookedFunctions, &g_memoryRegions);

		if (regionResult == TRUE) { g_inReadProcessMemory = false; return TRUE; }
		if (regionResult == -1)   { g_inReadProcessMemory = false; return FALSE; }

		BOOL result = o_ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		g_inReadProcessMemory = false;
		return result;
	}

	NTSTATUS NTAPI Hooked_NtReadVirtualMemory(
		HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
		SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead)
	{
		if (!o_NtReadVirtualMemory) return STATUS_NOT_IMPLEMENTED;
		if (ProcessHandle != GetCurrentProcess() && ProcessHandle != (HANDLE)-1)
			return o_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
		if (g_inReadProcessMemory)
			return o_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);

		g_inReadProcessMemory = true;

		if (g_hookedFunctions.empty() && g_memoryRegions.empty()) {
			NTSTATUS s = o_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
			g_inReadProcessMemory = false;
			return s;
		}

		uintptr_t addr = reinterpret_cast<uintptr_t>(BaseAddress);
		std::unique_lock<std::recursive_mutex> lock(g_antiDetectionMutex, std::try_to_lock);
		if (!lock.owns_lock()) {
			NTSTATUS s = o_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
			g_inReadProcessMemory = false;
			return s;
		}

		BOOL regionResult = CheckMemoryRegions_SEH(addr, Buffer, NumberOfBytesToRead, NumberOfBytesRead,
			&g_hookedFunctions, &g_memoryRegions);

		if (regionResult == TRUE) { g_inReadProcessMemory = false; return STATUS_SUCCESS; }
		if (regionResult == -1)   { g_inReadProcessMemory = false; return STATUS_ACCESS_DENIED; }

		NTSTATUS s = o_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
		g_inReadProcessMemory = false;
		return s;
	}

	NTSTATUS WINAPI Hooked_NtQueryInformationProcess(
		HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
		PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
	{
		if (!o_NtQueryInformationProcess) return STATUS_NOT_IMPLEMENTED;
		NTSTATUS status = o_NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
			ProcessInformation, ProcessInformationLength, ReturnLength);
		if (status != STATUS_SUCCESS) return status;
		if (ProcessHandle != GetCurrentProcess() && ProcessHandle != (HANDLE)-1) return status;

		switch (ProcessInformationClass) {
		case ProcessDebugPort:
			if (ProcessInformation && ProcessInformationLength >= sizeof(DWORD_PTR))
				*reinterpret_cast<DWORD_PTR*>(ProcessInformation) = 0;
			break;
		case TE_ProcessDebugObjectHandle:
			if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
				*reinterpret_cast<HANDLE*>(ProcessInformation) = nullptr;
				status = STATUS_INVALID_PARAMETER;
			}
			break;
		case TE_ProcessDebugFlags:
			if (ProcessInformation && ProcessInformationLength >= sizeof(DWORD))
				*reinterpret_cast<DWORD*>(ProcessInformation) = 1;
			break;
		default: break;
		}
		return status;
	}

	HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
	{
		if (!o_FindFirstFileA) return INVALID_HANDLE_VALUE;
		HANDLE result = o_FindFirstFileA(lpFileName, lpFindFileData);
		if (result != INVALID_HANDLE_VALUE && lpFindFileData) {
			std::string filename(lpFindFileData->cFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
			if (HasSuspiciousExtension(filename)) {
				FindClose(result);
				SetLastError(ERROR_NO_MORE_FILES);
				return INVALID_HANDLE_VALUE;
			}
		}
		return result;
	}

	BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
	{
		if (!o_FindNextFileA) return FALSE;
		BOOL result;
		do {
			result = o_FindNextFileA(hFindFile, lpFindFileData);
			if (!result) break;
			std::string filename(lpFindFileData->cFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
			if (!HasSuspiciousExtension(filename)) break;
		} while (result);
		return result;
	}

	BOOL WINAPI Hooked_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded)
	{
		if (!o_EnumProcessModules) return FALSE;
		if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1)
			return o_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);

		std::unique_lock<std::recursive_mutex> lock(g_antiDetectionMutex, std::try_to_lock);
		if (!lock.owns_lock())
			return o_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);

		BOOL result = o_EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded);
		if (result && lphModule && lpcbNeeded && *lpcbNeeded > 0) {
			auto hKernel32 = ::GetModuleHandleA("kernel32.dll");
			auto pGetModuleFileNameA = reinterpret_cast<decltype(&GetModuleFileNameA)>(
				::GetProcAddress(hKernel32, "GetModuleFileNameA"));
			if (!pGetModuleFileNameA) return result;

			DWORD moduleCount = cb / sizeof(HMODULE);
			DWORD filteredCount = 0;
			for (DWORD i = 0; i < moduleCount && i < (*lpcbNeeded / sizeof(HMODULE)); i++) {
				char modulePath[MAX_PATH] = { 0 };
				bool shouldHide = false;
				if (pGetModuleFileNameA(lphModule[i], modulePath, MAX_PATH)) {
					std::string modPath(modulePath);
					std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);
					size_t lastSlash = modPath.find_last_of("\\/");
					std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;
					if (HasSuspiciousExtension(modName)) shouldHide = true;
					for (const auto& [hiddenName, hiddenModule] : g_hiddenModules) {
						if (lphModule[i] == hiddenModule) { shouldHide = true; break; }
					}
				}
				if (!shouldHide) {
					if (filteredCount != i) lphModule[filteredCount] = lphModule[i];
					filteredCount++;
				}
			}
			*lpcbNeeded = filteredCount * sizeof(HMODULE);
		}
		return result;
	}

	DWORD WINAPI Hooked_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
	{
		if (!o_GetModuleFileNameA) return 0;
		if (g_inGetModuleFileName) return o_GetModuleFileNameA(hModule, lpFilename, nSize);

		g_inGetModuleFileName = true;
		DWORD result = o_GetModuleFileNameA(hModule, lpFilename, nSize);
		if (result && hModule != NULL) {
			std::string modPath(lpFilename);
			std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);
			size_t lastSlash = modPath.find_last_of("\\/");
			std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;
			if (HasSuspiciousExtension(modName)) {
				if (lpFilename && nSize > 0) lpFilename[0] = '\0';
				g_inGetModuleFileName = false;
				SetLastError(ERROR_MOD_NOT_FOUND);
				return 0;
			}
		}
		g_inGetModuleFileName = false;
		return result;
	}

	DWORD WINAPI Hooked_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
	{
		if (!o_GetModuleFileNameW) return 0;
		if (g_inGetModuleFileName) return o_GetModuleFileNameW(hModule, lpFilename, nSize);

		g_inGetModuleFileName = true;
		DWORD result = o_GetModuleFileNameW(hModule, lpFilename, nSize);
		if (result && hModule != NULL) {
			char narrowPath[MAX_PATH] = { 0 };
			WideCharToMultiByte(CP_ACP, 0, lpFilename, -1, narrowPath, MAX_PATH, NULL, NULL);
			std::string modPath(narrowPath);
			std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);
			size_t lastSlash = modPath.find_last_of("\\/");
			std::string modName = (lastSlash != std::string::npos) ? modPath.substr(lastSlash + 1) : modPath;
			if (HasSuspiciousExtension(modName)) {
				if (lpFilename && nSize > 0) lpFilename[0] = L'\0';
				g_inGetModuleFileName = false;
				SetLastError(ERROR_MOD_NOT_FOUND);
				return 0;
			}
		}
		g_inGetModuleFileName = false;
		return result;
	}

	BOOL WINAPI Hooked_Module32FirstW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
	{
		if (!o_Module32FirstW) return FALSE;
		if (g_inModule32) return o_Module32FirstW(hSnapshot, lpme);

		g_inModule32 = true;
		BOOL result = o_Module32FirstW(hSnapshot, lpme);
		while (result && lpme) {
			char narrowName[MAX_PATH] = { 0 };
			WideCharToMultiByte(CP_ACP, 0, lpme->szModule, -1, narrowName, MAX_PATH, NULL, NULL);
			std::string modName(narrowName);
			std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
			if (!HasSuspiciousExtension(modName) && !ShouldHideModule(lpme->hModule)) break;
			result = o_Module32NextW(hSnapshot, lpme);
		}
		g_inModule32 = false;
		return result;
	}

	BOOL WINAPI Hooked_Module32NextW(HANDLE hSnapshot, LPMODULEENTRY32W lpme)
	{
		if (!o_Module32NextW) return FALSE;
		if (g_inModule32) return o_Module32NextW(hSnapshot, lpme);

		g_inModule32 = true;
		BOOL result;
		do {
			result = o_Module32NextW(hSnapshot, lpme);
			if (!result) break;
			char narrowName[MAX_PATH] = { 0 };
			WideCharToMultiByte(CP_ACP, 0, lpme->szModule, -1, narrowName, MAX_PATH, NULL, NULL);
			std::string modName(narrowName);
			std::transform(modName.begin(), modName.end(), modName.begin(), ::tolower);
			if (!HasSuspiciousExtension(modName) && !ShouldHideModule(lpme->hModule)) break;
		} while (result);
		g_inModule32 = false;
		return result;
	}

	DWORD WINAPI Hooked_GetFileAttributesA(LPCSTR lpFileName)
	{
		if (!o_GetFileAttributesA) return INVALID_FILE_ATTRIBUTES;
		if (lpFileName) {
			std::string filename(lpFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
			size_t lastSlash = filename.find_last_of("\\/");
			std::string baseName = (lastSlash != std::string::npos) ? filename.substr(lastSlash + 1) : filename;
			if (HasSuspiciousExtension(baseName)) {
				SetLastError(ERROR_FILE_NOT_FOUND);
				return INVALID_FILE_ATTRIBUTES;
			}
		}
		return o_GetFileAttributesA(lpFileName);
	}

	DWORD WINAPI Hooked_GetFileAttributesW(LPCWSTR lpFileName)
	{
		if (!o_GetFileAttributesW) return INVALID_FILE_ATTRIBUTES;
		if (lpFileName) {
			char narrowPath[MAX_PATH] = { 0 };
			WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, narrowPath, MAX_PATH, NULL, NULL);
			std::string filename(narrowPath);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);
			size_t lastSlash = filename.find_last_of("\\/");
			std::string baseName = (lastSlash != std::string::npos) ? filename.substr(lastSlash + 1) : filename;
			if (HasSuspiciousExtension(baseName)) {
				SetLastError(ERROR_FILE_NOT_FOUND);
				return INVALID_FILE_ATTRIBUTES;
			}
		}
		return o_GetFileAttributesW(lpFileName);
	}

	// ---------- MinHook Install/Remove ----------

	// Helper to install a single hook via MinHook and track it
	static bool InstallHook(LPVOID pTarget, LPVOID pDetour, LPVOID* ppOriginal, const char* name)
	{
		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);

		MH_STATUS status = MH_CreateHook(pTarget, pDetour, ppOriginal);
		if (status != MH_OK) {
			te::sdk::helper::logging::Log("[#TE] MH_CreateHook failed for %s: %s", name, MH_StatusToString(status));
			return false;
		}

		status = MH_EnableHook(pTarget);
		if (status != MH_OK) {
			te::sdk::helper::logging::Log("[#TE] MH_EnableHook failed for %s: %s", name, MH_StatusToString(status));
			MH_RemoveHook(pTarget);
			return false;
		}

		// Backup original bytes for integrity check spoofing
		HookedFunction hf;
		hf.functionName = name;
		hf.pTarget = pTarget;
		hf.pTrampoline = *ppOriginal;
		hf.isActive = true;
		hf.originalBytes.resize(16);
		SafeMemoryCopy_Internal(hf.originalBytes.data(), pTarget, 16);
		g_hookedFunctions.push_back(std::move(hf));

		te::sdk::helper::logging::Log("[#TE] Hooked %s at %p (MinHook)", name, pTarget);
		return true;
	}
	BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
	static bool InstallHWIDSpoofHooks();
	bool InstallAntiDetectionHooks()
	{
		if (g_hooksInitialized) {
			te::sdk::helper::logging::Log("[#TE] Hooks already initialized");
			return true;
		}

		te::sdk::helper::logging::Log("[#TE] Installing anti-detection hooks (MinHook)");

		// Initialize MinHook
		if (!g_minhookInitialized) {
			MH_STATUS status = MH_Initialize();
			if (status != MH_OK && status != MH_ERROR_ALREADY_INITIALIZED) {
				te::sdk::helper::logging::Log("[#TE] MH_Initialize failed: %s", MH_StatusToString(status));
				return false;
			}
			g_minhookInitialized = true;
		}

		HMODULE hKernel32 = ::GetModuleHandleA("kernel32.dll");
		HMODULE hNtdll = ::GetModuleHandleA("ntdll.dll");
		HMODULE hPsapi = ::LoadLibraryA("psapi.dll");

		if (!hKernel32 || !hNtdll) {
			te::sdk::helper::logging::Log("[#TE] Failed to get module handles (K32: %p, Ntdll: %p)", hKernel32, hNtdll);
			return false;
		}

		g_hooksInitialized = true;
		bool success = true;
		int hookCount = 0;

		// Kernel32 hooks
		#define INSTALL_K32(func) do { \
			success &= InstallHook(::GetProcAddress(hKernel32, #func), \
				reinterpret_cast<LPVOID>(Hooked_##func), \
				reinterpret_cast<LPVOID*>(&o_##func), #func); \
			hookCount++; \
		} while(0)

		INSTALL_K32(VirtualQuery);
		INSTALL_K32(VirtualQueryEx);
		INSTALL_K32(ReadProcessMemory);
		INSTALL_K32(FindFirstFileA);
		INSTALL_K32(FindNextFileA);
		INSTALL_K32(GetModuleFileNameA);
		INSTALL_K32(GetModuleFileNameW);
		INSTALL_K32(GetFileAttributesA);
		INSTALL_K32(GetFileAttributesW);
		INSTALL_K32(Module32FirstW);
		INSTALL_K32(Module32NextW);

		#undef INSTALL_K32

		// PSAPI hook
		if (hPsapi) {
			success &= InstallHook(::GetProcAddress(hPsapi, "EnumProcessModules"),
				reinterpret_cast<LPVOID>(Hooked_EnumProcessModules),
				reinterpret_cast<LPVOID*>(&o_EnumProcessModules), "EnumProcessModules");
			hookCount++;
		}

		// Ntdll hooks
		#define INSTALL_NT(func) do { \
			success &= InstallHook(::GetProcAddress(hNtdll, #func), \
				reinterpret_cast<LPVOID>(Hooked_##func), \
				reinterpret_cast<LPVOID*>(&o_##func), #func); \
			hookCount++; \
		} while(0)

		INSTALL_NT(NtQueryVirtualMemory);
		INSTALL_NT(NtReadVirtualMemory);
		INSTALL_NT(NtQueryInformationProcess);

		#undef INSTALL_NT

		// VirtualProtect monitor (to detect FZ making pages executable)
		success &= InstallHook(::GetProcAddress(hKernel32, "VirtualProtect"),
			reinterpret_cast<LPVOID>(Hooked_VirtualProtect),
			reinterpret_cast<LPVOID*>(&o_VirtualProtect), "VirtualProtect");
		hookCount++;

		if (!success) {
			te::sdk::helper::logging::Log("[#TE] Some hooks failed (attempted %d)", hookCount);
			g_hooksInitialized = false;
			return false;
		}

		te::sdk::helper::logging::Log("[#TE] All %d hooks installed successfully (MinHook)", hookCount);

		// Install HWID spoofing hooks (API-level hardware enumeration spoofing)
		InstallHWIDSpoofHooks();

		return true;
	}

	void RegisterHiddenModule(const std::string& name, HMODULE module)
	{
		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
		g_hiddenModules[name] = module;
		te::sdk::helper::logging::Log("[#TE] Registered hidden module: %s at %p", name.c_str(), module);
	}

	void RemoveAntiDetectionHooks()
	{
		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);
		g_hooksInitialized = false;

		for (auto& hook : g_hookedFunctions) {
			if (!hook.isActive) continue;
			MH_STATUS status = MH_DisableHook(hook.pTarget);
			if (status == MH_OK) {
				MH_RemoveHook(hook.pTarget);
				hook.isActive = false;
				te::sdk::helper::logging::Log("[#TE] Unhooked %s", hook.functionName.c_str());
			}
			else {
				te::sdk::helper::logging::Log("[#TE] Failed to unhook %s: %s",
					hook.functionName.c_str(), MH_StatusToString(status));
			}
		}

		g_hookedFunctions.clear();
		g_memoryRegions.clear();
		g_hiddenModules.clear();

		te::sdk::helper::logging::Log("[#TE] All hooks removed");
	}

	// ---------- VirtualProtect Monitor ----------
	// Tracks when FZ makes pages executable (needed to find real FZ code)

	thread_local bool g_inVirtualProtect = false;

	// Log of pages made executable by FZ
	struct ExecPage { uintptr_t addr; SIZE_T size; DWORD newProt; };
	static std::vector<ExecPage> g_newExecPages;
	static std::mutex g_execPagesMutex;

	// SEH-safe hex dump helper
	extern "C" void __stdcall HexDumpRegion_SEH(uintptr_t addr, char* outBuf, size_t outBufSize)
	{
		__try {
			auto p = reinterpret_cast<const uint8_t*>(addr);
			size_t pos = 0;
			for (int i = 0; i < 32 && pos + 3 < outBufSize; i++) {
				pos += snprintf(outBuf + pos, outBufSize - pos, "%02X ", p[i]);
			}
			if (pos > 0) outBuf[pos - 1] = '\0';
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			snprintf(outBuf, outBufSize, "<access violation>");
		}
	}

	BOOL WINAPI Hooked_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
	{
		if (g_inVirtualProtect) return o_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
		g_inVirtualProtect = true;

		BOOL result = o_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

		if (result && (flNewProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
		{
			auto addr = reinterpret_cast<uintptr_t>(lpAddress);

			// Skip obviously invalid entries (not page-aligned or tiny size)
			if ((addr & 0xFFF) != 0 || dwSize < 0x100) {
				g_inVirtualProtect = false;
				return result;
			}

			// Only log PRIVATE pages (FZ code, not system DLLs)
			MEMORY_BASIC_INFORMATION mbi;
			auto vq = o_VirtualQuery ? o_VirtualQuery : VirtualQuery;
			if (vq(lpAddress, &mbi, sizeof(mbi)) == sizeof(mbi) && mbi.Type == MEM_PRIVATE) {
				// Hex dump first 32 bytes for diagnostics
				char hexDump[128] = {};
				HexDumpRegion_SEH(addr, hexDump, sizeof(hexDump));

				//te::sdk::helper::logging::Log("[#TE FZ] VP->EXEC: 0x%08X +0x%X prot=0x%02X (was 0x%02X) [%s]",
				//	addr, (uint32_t)dwSize, flNewProtect, lpflOldProtect ? *lpflOldProtect : 0, hexDump);

				std::lock_guard<std::mutex> lock(g_execPagesMutex); 
				g_newExecPages.push_back({ addr, dwSize, flNewProtect });
			}
		}

		g_inVirtualProtect = false;
		return result;
	}

	// ---------- HWID Spoofing (API-level) ----------
	// Hooks hardware enumeration APIs to return spoofed values when called from FZ code.
	// Values are generated once per session for consistency.

	struct SpoofedHWID {
		DWORD volumeSerial;
		char volumeSerialStr[16];
		char driveSerial[64];
		char gpuName[128];
		char cpuBrand[64];
		DWORD totalRAM_KB;
		DWORD processorCount;
		int keyboardType;
		int keyboardSubType;
		int keyboardFuncKeys;
		bool initialized;
	};

	static SpoofedHWID g_spoof = {};
	static uintptr_t g_fzModuleBase = 0;
	static uintptr_t g_fzModuleSize = 0;

	static void InitSpoofedHWID()
	{
		if (g_spoof.initialized) return;

		srand(GetTickCount() ^ 0xDEADBEEF);

		// Volume serial - random 32-bit value
		g_spoof.volumeSerial = (DWORD)(rand() << 16) | (DWORD)rand();
		snprintf(g_spoof.volumeSerialStr, sizeof(g_spoof.volumeSerialStr), "%04X-%04X",
			(g_spoof.volumeSerial >> 16) & 0xFFFF, g_spoof.volumeSerial & 0xFFFF);

		// Physical drive serial - random alphanumeric
		static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		int serialLen = 16 + rand() % 8;
		for (int i = 0; i < serialLen && i < 63; i++)
			g_spoof.driveSerial[i] = charset[rand() % (sizeof(charset) - 1)];
		g_spoof.driveSerial[serialLen] = '\0';

		// GPU name
		static const char* gpus[] = {
			"NVIDIA GeForce RTX 4080", "AMD Radeon RX 7900 XTX",
			"NVIDIA GeForce RTX 3070", "AMD Radeon RX 6800 XT",
			"NVIDIA GeForce GTX 1660 Ti", "AMD Radeon RX 5700 XT",
			"NVIDIA GeForce RTX 4060", "NVIDIA GeForce RTX 3060"
		};
		strncpy(g_spoof.gpuName, gpus[rand() % 8], sizeof(g_spoof.gpuName) - 1);

		// CPU brand
		static const char* cpus[] = {
			"Intel(R) Core(TM) i9-14900K Processor",
			"AMD Ryzen 9 5900X 12-Core Processor",
			"Intel(R) Core(TM) i7-13700K Processor",
			"AMD Ryzen 7 5800X 8-Core Processor",
			"Intel(R) Core(TM) i5-12600K Processor",
			"AMD Ryzen 5 5600X 6-Core Processor"
		};
		strncpy(g_spoof.cpuBrand, cpus[rand() % 6], sizeof(g_spoof.cpuBrand) - 1);

		// RAM (8-32 GB in KB)
		g_spoof.totalRAM_KB = (DWORD)(8 + rand() % 25) * 1024 * 1024;

		// Processor count (4-16)
		g_spoof.processorCount = 4 + rand() % 13;

		// Keyboard type info
		g_spoof.keyboardType = 4 + rand() % 4;     // Type 4-7
		g_spoof.keyboardSubType = rand() % 12;      // Subtype
		g_spoof.keyboardFuncKeys = 12;               // Always 12 function keys

		g_spoof.initialized = true;

		te::sdk::helper::logging::Log("[#TE FZ] HWID spoof initialized: GPU=%s CPU=%s Vol=%s Drive=%s RAM=%uKB Procs=%u",
			g_spoof.gpuName, g_spoof.cpuBrand, g_spoof.volumeSerialStr,
			g_spoof.driveSerial, g_spoof.totalRAM_KB, g_spoof.processorCount);
	}

	// Check if the calling function is within FZ module address range
	static bool IsCallerFZ(void* retAddr)
	{
		if (!g_fzModuleBase || !g_fzModuleSize) return false;
		auto addr = reinterpret_cast<uintptr_t>(retAddr);
		return addr >= g_fzModuleBase && addr < g_fzModuleBase + g_fzModuleSize;
	}

	// Resolve FZ module size from PE header (SizeOfImage)
	extern "C" uint32_t __stdcall GetPESizeOfImage_SEH(uintptr_t base)
	{
		__try {
			uint32_t peOff = *reinterpret_cast<const uint32_t*>(base + 0x3C);
			if (peOff == 0 || peOff > 0x1000) return 0;
			// SizeOfImage is at PE + 0x50 (offset 80 from COFF header start = PE+4+20+56)
			return *reinterpret_cast<const uint32_t*>(base + peOff + 0x50);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
	}

	// --- P0: Drive serial spoofing ---

	static decltype(&GetVolumeInformationA) o_GetVolumeInformationA = nullptr;
	static decltype(&DeviceIoControl)       o_DeviceIoControl = nullptr;

	static BOOL WINAPI Hooked_GetVolumeInformationA(
		LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
		LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength,
		LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
	{
		BOOL result = o_GetVolumeInformationA(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize,
			lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags,
			lpFileSystemNameBuffer, nFileSystemNameSize);

		if (result && g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			if (lpVolumeSerialNumber) {
				te::sdk::helper::logging::Log("[#TE FZ] GetVolumeInfoA spoofed serial: 0x%08X -> 0x%08X",
					*lpVolumeSerialNumber, g_spoof.volumeSerial);
				*lpVolumeSerialNumber = g_spoof.volumeSerial;
			}
		}
		return result;
	}

	static BOOL WINAPI Hooked_DeviceIoControl(
		HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
		LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
	{
		BOOL result = o_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize,
			lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);

		if (result && g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			// IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400
			if (dwIoControlCode == 0x002D1400 && lpOutBuffer && nOutBufferSize >= 48) {
				// STORAGE_DEVICE_DESCRIPTOR: SerialNumberOffset is at byte offset 12
				auto desc = reinterpret_cast<uint8_t*>(lpOutBuffer);
				uint32_t serialOffset = *reinterpret_cast<uint32_t*>(desc + 12);
				if (serialOffset > 0 && serialOffset < nOutBufferSize - 1) {
					char* serial = reinterpret_cast<char*>(desc + serialOffset);
					size_t maxLen = nOutBufferSize - serialOffset - 1;
					size_t copyLen = strlen(g_spoof.driveSerial);
					if (copyLen > maxLen) copyLen = maxLen;
					memcpy(serial, g_spoof.driveSerial, copyLen);
					serial[copyLen] = '\0';
					te::sdk::helper::logging::Log("[#TE FZ] DeviceIoControl spoofed drive serial -> %s", g_spoof.driveSerial);
				}
			}
		}
		return result;
	}

	// --- P1: Display/Memory/System spoofing ---

	static decltype(&EnumDisplayDevicesA) o_EnumDisplayDevicesA = nullptr;

	static BOOL WINAPI Hooked_EnumDisplayDevicesA(
		LPCSTR lpDevice, DWORD iDevNum, PDISPLAY_DEVICEA lpDisplayDevice, DWORD dwFlags)
	{
		BOOL result = o_EnumDisplayDevicesA(lpDevice, iDevNum, lpDisplayDevice, dwFlags);

		if (result && g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			if (lpDisplayDevice && iDevNum == 0) {
				te::sdk::helper::logging::Log("[#TE FZ] EnumDisplayDevicesA spoofed: %s -> %s",
					lpDisplayDevice->DeviceString, g_spoof.gpuName);
				strncpy(lpDisplayDevice->DeviceString, g_spoof.gpuName,
					sizeof(lpDisplayDevice->DeviceString) - 1);
			}
		}
		return result;
	}

	static decltype(&GlobalMemoryStatusEx) o_GlobalMemoryStatusEx = nullptr;

	static BOOL WINAPI Hooked_GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
	{
		BOOL result = o_GlobalMemoryStatusEx(lpBuffer);

		if (result && g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			lpBuffer->ullTotalPhys = (DWORDLONG)g_spoof.totalRAM_KB * 1024ULL;
			te::sdk::helper::logging::Log("[#TE FZ] GlobalMemoryStatusEx spoofed -> %u KB", g_spoof.totalRAM_KB);
		}
		return result;
	}

	static decltype(&GetSystemInfo) o_GetSystemInfo = nullptr;

	static VOID WINAPI Hooked_GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)
	{
		o_GetSystemInfo(lpSystemInfo);

		if (g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			lpSystemInfo->dwNumberOfProcessors = g_spoof.processorCount;
			te::sdk::helper::logging::Log("[#TE FZ] GetSystemInfo spoofed procs -> %u", g_spoof.processorCount);
		}
	}

	// --- P2: Keyboard type spoofing ---

	static decltype(&GetKeyboardType) o_GetKeyboardType = nullptr;

	static int WINAPI Hooked_GetKeyboardType(int nTypeFlag)
	{
		int result = o_GetKeyboardType(nTypeFlag);

		if (g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			switch (nTypeFlag) {
			case 0: result = g_spoof.keyboardType; break;
			case 1: result = g_spoof.keyboardSubType; break;
			case 2: result = g_spoof.keyboardFuncKeys; break;
			}
		}
		return result;
	}

	// --- P2: CPU info via registry spoofing ---

	static decltype(&RegQueryValueExA) o_RegQueryValueExA = nullptr;

	static LSTATUS WINAPI Hooked_RegQueryValueExA(
		HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
		LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
	{
		LSTATUS result = o_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);

		if (result == ERROR_SUCCESS && g_spoof.initialized && IsCallerFZ(_ReturnAddress())) {
			if (lpValueName && lpData && lpcbData) {
				// Spoof CPU brand string from HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0
				if (_stricmp(lpValueName, "ProcessorNameString") == 0) {
					DWORD needed = (DWORD)strlen(g_spoof.cpuBrand) + 1;
					if (*lpcbData >= needed) {
						memcpy(lpData, g_spoof.cpuBrand, needed);
						*lpcbData = needed;
						te::sdk::helper::logging::Log("[#TE FZ] RegQueryValueExA spoofed ProcessorNameString -> %s", g_spoof.cpuBrand);
					}
				}
			}
		}
		return result;
	}

	// Install HWID spoofing hooks (called after MinHook is initialized)
	static bool InstallHWIDSpoofHooks()
	{
		InitSpoofedHWID();

		HMODULE hKernel32 = ::GetModuleHandleA("kernel32.dll");
		HMODULE hUser32 = ::GetModuleHandleA("user32.dll");
		HMODULE hAdvapi32 = ::LoadLibraryA("advapi32.dll");

		bool success = true;
		int count = 0;

		// P0: Drive serial
		if (hKernel32) {
			success &= InstallHook(::GetProcAddress(hKernel32, "GetVolumeInformationA"),
				reinterpret_cast<LPVOID>(Hooked_GetVolumeInformationA),
				reinterpret_cast<LPVOID*>(&o_GetVolumeInformationA), "GetVolumeInformationA");
			count++;

			success &= InstallHook(::GetProcAddress(hKernel32, "DeviceIoControl"),
				reinterpret_cast<LPVOID>(Hooked_DeviceIoControl),
				reinterpret_cast<LPVOID*>(&o_DeviceIoControl), "DeviceIoControl");
			count++;

			success &= InstallHook(::GetProcAddress(hKernel32, "GlobalMemoryStatusEx"),
				reinterpret_cast<LPVOID>(Hooked_GlobalMemoryStatusEx),
				reinterpret_cast<LPVOID*>(&o_GlobalMemoryStatusEx), "GlobalMemoryStatusEx");
			count++;

			success &= InstallHook(::GetProcAddress(hKernel32, "GetSystemInfo"),
				reinterpret_cast<LPVOID>(Hooked_GetSystemInfo),
				reinterpret_cast<LPVOID*>(&o_GetSystemInfo), "GetSystemInfo");
			count++;
		}

		// P1: Display
		if (hUser32) {
			success &= InstallHook(::GetProcAddress(hUser32, "EnumDisplayDevicesA"),
				reinterpret_cast<LPVOID>(Hooked_EnumDisplayDevicesA),
				reinterpret_cast<LPVOID*>(&o_EnumDisplayDevicesA), "EnumDisplayDevicesA");
			count++;

			success &= InstallHook(::GetProcAddress(hUser32, "GetKeyboardType"),
				reinterpret_cast<LPVOID>(Hooked_GetKeyboardType),
				reinterpret_cast<LPVOID*>(&o_GetKeyboardType), "GetKeyboardType");
			count++;
		}

		// P2: Registry CPU info
		if (hAdvapi32) {
			success &= InstallHook(::GetProcAddress(hAdvapi32, "RegQueryValueExA"),
				reinterpret_cast<LPVOID>(Hooked_RegQueryValueExA),
				reinterpret_cast<LPVOID*>(&o_RegQueryValueExA), "RegQueryValueExA");
			count++;
		}

		te::sdk::helper::logging::Log("[#TE FZ] HWID spoof hooks: %d installed, success=%d", count, success);
		return success;
	}

	// ---------- FenixZone Internal Function Hooks ----------

	// Known FenixZone function signatures
	// From original bypass code (obfuscated binary):
	constexpr auto SIG_FENIXZONE_CHAT_PUSH  = "55 0F BA FD 27 F5 89 E5 57 F9 66 F7 C6 ? ? 3B D6 56 8D B5 ? ? ? ? E9 ? ? ? ?";
	constexpr auto SIG_MESSAGE_NUMBER       = "C7 05 ? ? ? ? ? ? ? ? E8 ? ? ? ? C7 44 24";
	// Legacy GCC signatures (older FZ versions):
	constexpr auto SIG_FENIXZONE_CLOSE      = "55 89 E5 83 EC 18 C7 05 ? ? ? ? ? ? ? ?";
	constexpr auto SIG_FENIXZONE_TIMER_FUNC = "55 89 E5 57 56 53 81 EC ? ? ? ? 83 3D ? ? ? ?";

	// FZ internal hook state
	static bool g_fzInternalHooked = false;
	static int g_timerStep = 0;

	// Trampoline pointers for FZ internal hooks
	typedef int(__stdcall* FZ_ChatPush_t)(int);
	static FZ_ChatPush_t o_FZ_ChatPush = nullptr;

	typedef void(__stdcall* FZ_TerminateGTA_t)(HWND, UINT, UINT_PTR, DWORD);
	static FZ_TerminateGTA_t o_FZ_TerminateGTA = nullptr;

	using FZ_TimerFunc_t = void(__cdecl*)(
		struct _WIN32_FIND_DATAA*, signed int, struct _FILETIME*,
		HWND, UINT, UINT_PTR, DWORD);
	static FZ_TimerFunc_t o_FZ_TimerFunc = nullptr;

	// SendCommand: cdecl export, takes const char* command string
	typedef void(__cdecl* FZ_SendCommand_t)(const char* cmd);
	static FZ_SendCommand_t o_FZ_SendCommand = nullptr;

	// ---------- HW Data Spoofing for /buto ----------

	static std::string RandomHex()
	{
		std::stringstream ss;
		ss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << (rand() & 0xFFFFFFFF);
		return ss.str();
	}

	static std::string RandomMonitorID()
	{
		static const char* vendors[] = { "AUO", "CMN", "LGD", "SHP", "BOE" };
		return vendors[rand() % 5] + std::to_string(1000 + rand() % 9000);
	}

	static std::string RandomResolution()
	{
		static const char* resolutions[] = { "1920X1080", "2560X1440", "1366X768", "1600X900", "3440X1440" };
		return resolutions[rand() % 5];
	}

	static std::string RandomRAM()
	{
		int ramMb = (8 + rand() % 24) * 1024;
		return std::to_string(ramMb * 1024) + " KB";
	}

	static std::string RandomCPU()
	{
		static const char* cpus[] = {
			"Intel(R) Core(TM) i9-14900K", "AMD Ryzen 9 5900X",
			"Intel(R) Core(TM) i5-12600H", "AMD Ryzen 7 7840HS"
		};
		return cpus[rand() % 4];
	}

	static std::string GetRandomDisplayDevice()
	{
		static const char* devices[] = {
			"NVIDIA GeForce RTX 4080", "AMD Radeon RX 7900 XTX",
			"NVIDIA GeForce RTX 3070", "AMD Radeon RX 6800 XT",
			"NVIDIA GeForce GTX 1660 Ti", "AMD Radeon RX 5700 XT"
		};
		return devices[rand() % 6];
	}

	static std::string GetRandomCPUBrand()
	{
		static const char* brands[] = { "GenuineIntel", "AuthenticAMD", "CentaurHauls" };
		return brands[rand() % 3];
	}

	static std::string GenerateRandomCPUID()
	{
		uint32_t eax = 0x00000001 + (rand() & 0xFFFF);
		uint32_t edx = 0x078BFBFF + (rand() & 0xFFFF);
		uint32_t ecx = 0x7FFAFBBF + (rand() & 0xFFFF);
		char buffer[64];
		snprintf(buffer, sizeof(buffer), "0x%08X 0x%08X 0x%08X", eax, edx, ecx);
		return std::string(buffer);
	}

	static bool IsSpoofableCommand(const std::string& line)
	{
		// Only spoof HWID report commands (CLA/DRA/MON), not plain /buto hex tokens
		return line.find("/buto CLA:") != std::string::npos ||
		       line.find("/buto DRA:") != std::string::npos ||
		       line.find("/quto MON:") != std::string::npos;
	}

	static std::string ReplaceHexWithRandom(const std::string& input)
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

	static std::string RandomDRA()
	{
		static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		const int length = 15;
		std::string result = "dRA";
		for (int i = 0; i < length; i++) {
			result += charset[rand() % (sizeof(charset) - 1)];
		}
		return result;
	}

	static std::string SpoofCommandHWData(const std::string& input)
	{
		try
		{
			if (!IsSpoofableCommand(input))
				return input;

			std::string output = input;

			// Spoof DRA identifier (must start with "dRA")
			output = std::regex_replace(output,
				std::regex(R"(\bdRA[A-Za-z0-9]{10,20}\b)"),
				RandomDRA());

			// Spoof display device (EnumDisplayDevicesA)
			output = std::regex_replace(output,
				std::regex(R"(\b(?:NVIDIA|AMD|Intel).*?(?:RTX|GTX|Radeon|Arc).*?\b)"),
				GetRandomDisplayDevice());

			// Spoof memory (GlobalMemoryStatusEx)
			output = std::regex_replace(output, std::regex(R"(\b\d{7,9} KB\b)"), RandomRAM());

			// Spoof processor count (GetSystemInfo)
			output = std::regex_replace(output,
				std::regex(R"(\b(\d{1,2})(?= \d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}))"),
				std::to_string(4 + rand() % 13));

			// Spoof keyboard type info (GetKeyboardType)
			output = std::regex_replace(output,
				std::regex(R"(\b\d{1,2}-\d{1,2}-\d{1,2}-\d{1,2}\b)"),
				std::to_string(4 + rand() % 4) + "-" +
				std::to_string(rand() % 12) + "-" +
				std::to_string(1 + rand() % 12) + "-" +
				std::to_string(43 + rand() % 10));

			// Spoof CPU brand string (CPUID)
			output = std::regex_replace(output,
				std::regex(R"(\b(?:GenuineIntel|AuthenticAMD|CentaurHauls)\b)"),
				GetRandomCPUBrand());

			// Spoof CPU model info
			output = std::regex_replace(output,
				std::regex(R"((\d+(?:th)? Gen .+? Core\(TM\) .+?))"),
				RandomCPU());

			// Spoof CPUID register values
			output = std::regex_replace(output,
				std::regex(R"(0x[0-9A-Fa-f]{8} 0x[0-9A-Fa-f]{8} 0x[0-9A-Fa-f]{8})"),
				GenerateRandomCPUID());

			// Spoof remaining hex values
			output = ReplaceHexWithRandom(output);

			// Spoof monitor info
			output = std::regex_replace(output, std::regex(R"(\b[A-Z]{3}\d{4}\b)"), RandomMonitorID());
			output = std::regex_replace(output, std::regex(R"(\b\d{3,4}X\d{3,4}\b)"), RandomResolution());

			te::sdk::helper::logging::Log("[#TE FZ] Spoofed hardware identifiers: %s", output.c_str());

			return output;
		}
		catch (const std::exception& e)
		{
			te::sdk::helper::logging::Log("[#TE FZ] SpoofCommandHWData exception: %s", e.what());
		}
		return input;
	}

	// ---------- ChatPush Hook (__stdcall, int param = string ptr) ----------

	static int __stdcall Hooked_ChatPush(int a1)
	{
		try {
			auto str = reinterpret_cast<char*>(a1);
			if (!str || IsBadStringPtrA(str, 256))
				return o_FZ_ChatPush(a1);

			auto spoofedCommand = SpoofCommandHWData(str);

			te::sdk::helper::logging::Log("[#TE FZ] CHAT_PUSH: %s", spoofedCommand.c_str());

			// Only modify if spoofing changed something, respect original buffer size
			if (spoofedCommand != str) {
				size_t origLen = strlen(str);
				size_t copyLen = (std::min)(spoofedCommand.length(), origLen);
				memcpy(str, spoofedCommand.c_str(), copyLen);
				str[copyLen] = '\0';
			}
		}
		catch (...) {
			te::sdk::helper::logging::Log("[#TE FZ] CHAT_PUSH exception in hook");
		}

		return o_FZ_ChatPush(a1);
	}

	// ---------- SendCommand Hook (cdecl, intercepts all FZ commands) ----------

	static void __cdecl Hooked_SendCommand(const char* cmd)
	{
		try {
			if (cmd && !IsBadStringPtrA(cmd, 512)) {
				std::string spoofed = SpoofCommandHWData(cmd);
				te::sdk::helper::logging::Log("[#TE FZ] SendCommand: %s", spoofed.c_str());
				o_FZ_SendCommand(spoofed.c_str());
				return;
			}
		}
		catch (...) {
			te::sdk::helper::logging::Log("[#TE FZ] SendCommand exception in hook");
		}
		o_FZ_SendCommand(cmd);
	}

	// ---------- TerminateGTA Hook (NOP - prevent game close) ----------

	static void __stdcall hkTerminateGTA(HWND hWnd, UINT msg, UINT_PTR idEvent, DWORD dwTime)
	{
		//te::sdk::helper::logging::Log("[#TE FZ] TerminateGTA blocked (HWND: %p, msg: %u)", hWnd, msg);
		// NOP - do nothing, prevent FZ from closing the game
	}

	// ---------- TimerFunc Hook (generate /buto responses) ----------

	static void __cdecl hkTimerFunc(
		struct _WIN32_FIND_DATAA* FirstFileA,
		signed int cFileName,
		struct _FILETIME* p_Buffer,
		HWND a4,
		UINT a5,
		UINT_PTR a6,
		DWORD a7)
	{
		o_FZ_TimerFunc(FirstFileA, cFileName, p_Buffer, a4, a5, a6, a7);
	}

	// ---------- Delayed FZ Memory Scanner ----------
	// FZ loading chain: RPC 61 delivers PE(s) -> one of them manual-maps a MPRESS DLL internally
	// We allow FZ PEs through, wait for the chain to complete, then scan executable memory

	static bool g_scannerStarted = false;

	// Cached pattern parser for ScanExecutableMemory
	static std::unordered_map<std::string, PatternData> s_patternCache;

	static PatternData& ParsePattern(const char* sig)
	{
		auto it = s_patternCache.find(sig);
		if (it != s_patternCache.end()) return it->second;

		PatternData pd;
		const char* cur = sig;
		while (*cur)
		{
			if (*cur == '?') {
				++cur;
				if (*cur == '?') ++cur;
				pd.bytes.push_back(0);
				pd.mask.push_back(0);
			}
			else if (isxdigit(static_cast<unsigned char>(*cur))) {
				pd.bytes.push_back(static_cast<uint8_t>(strtoul(cur, const_cast<char**>(&cur), 16)));
				pd.mask.push_back(1);
			}
			else {
				++cur;
			}
		}
		pd.firstWildcard = !pd.mask.empty() ? !pd.mask[0] : true;
		pd.firstByte = !pd.bytes.empty() ? pd.bytes[0] : 0;
		return s_patternCache.emplace(sig, std::move(pd)).first->second;
	}

	// SEH-protected pattern scan of a single memory region
	extern "C" uintptr_t __stdcall ScanRegion_SEH(
		const uint8_t* region, size_t regionSize,
		const uint8_t* patBytes, const uint8_t* patMask, size_t pLen,
		uint8_t firstByte, bool firstWildcard, int* pSkipCount)
	{
		__try {
			const uint8_t* cur = region;
			const uint8_t* end = region + regionSize - pLen;
			while (cur <= end) {
				if (!firstWildcard) {
					cur = static_cast<const uint8_t*>(memchr(cur, firstByte, (end - cur) + 1));
					if (!cur) return 0;
				}
				bool ok = true;
				for (size_t j = 0; j < pLen; ++j) {
					if (patMask[j] && cur[j] != patBytes[j]) { ok = false; break; }
				}
				if (ok) {
					if (*pSkipCount > 0) { --(*pSkipCount); ++cur; continue; }
					return reinterpret_cast<uintptr_t>(cur);
				}
				++cur;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// Access violation scanning this region - skip it
		}
		return 0;
	}

	// Pattern scan across executable memory regions only
	// skipCount: skip first N matches (0 = return first match)
	static uintptr_t ScanExecutableMemory(const char* signature, int skipCount = 0)
	{
		auto& pat = ParsePattern(signature);
		size_t pLen = pat.bytes.size();
		if (pLen == 0) return 0;

		MEMORY_BASIC_INFORMATION mbi;
		uintptr_t address = 0x10000;

		while (o_VirtualQuery ? o_VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == sizeof(mbi)
			: VirtualQuery(reinterpret_cast<void*>(address), &mbi, sizeof(mbi)) == sizeof(mbi))
		{
			if (mbi.State == MEM_COMMIT
				&& (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE)
				&& (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				&& !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
				&& mbi.RegionSize >= pLen)
			{
				auto region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
				uintptr_t result = ScanRegion_SEH(region, mbi.RegionSize,
					pat.bytes.data(), pat.mask.data(), pLen,
					pat.firstByte, pat.firstWildcard, &skipCount);
				if (result) return result;
			}
			address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
			if (address < reinterpret_cast<uintptr_t>(mbi.BaseAddress)) break;
		}
		return 0;
	}


	// ---------- CreateThread Patching ----------

	struct ThreadSig {
		const char* name;
		const char* pattern;
		bool skipFirst;
		uintptr_t resolvedAddress = 0;
	};

	static std::vector<ThreadSig> g_threadSigs;

	static void PrepareThreadSigs()
	{
		g_threadSigs.clear();
		g_threadSigs.push_back({ "block_1", "55 89 E5 83 EC 08 E8 ? ? ? ?", true });
		g_threadSigs.push_back({ "block_2", "55 89 E5 53 31 DB 83 EC 24 E8 ? ? ? ? 8D 55 F4 C7 45 ? ? ? ? ? 89 54 24 04 89 04 24 E8 ? ? ? ? 51", false });
		g_threadSigs.push_back({ "block_3", "55 89 E5 53 31 DB 83 EC 24 E8 ? ? ? ? 8D 55 F4 C7 45 ? ? ? ? ? 89 54 24 04 89 04 24 E8 ? ? ? ? 52", false });
		g_threadSigs.push_back({ "block_4", "55 89 E5 83 EC 28 E8 ? ? ? ?", false });
		g_threadSigs.push_back({ "block_5", "55 89 E5 57 56 53 81 EC ? ? ? ? C7 04 24 ? ? ? ? E8 ? ? ? ? 89 85 ? ? ? ?", false });

		for (auto& sig : g_threadSigs) {
			uintptr_t match = ScanExecutableMemory(sig.pattern, sig.skipFirst ? 1 : 0);
			if (match) {
				sig.resolvedAddress = match;
				te::sdk::helper::logging::Log("[#TE FZ] ThreadSig %s at 0x%08X", sig.name, match);
			}
		}
	}

	static uintptr_t Get_CreateThreadFunction()
	{
		auto sigCall = "E8 ? ? ? ? 83 EC 0C C9";
		uintptr_t match = ScanExecutableMemory(sigCall);
		if (!match) return 0;

		int32_t relOffset = *reinterpret_cast<int32_t*>(match + 1);
		uintptr_t targetAddr = match + 5 + relOffset;
		te::sdk::helper::logging::Log("[#TE FZ] CreateThread initializer at 0x%08X", targetAddr);
		return targetAddr;
	}

	static size_t GetFunctionSizeByRetn(uintptr_t funcAddr, size_t maxScanSize = 0x1000)
	{
		auto code = reinterpret_cast<uint8_t*>(funcAddr);
		for (size_t i = 0; i + 2 < maxScanSize; ++i) {
			if (code[i] == 0xC2 && code[i + 1] == 0x0C && code[i + 2] == 0x00)
				return i + 3;
		}
		return 0;
	}

	static bool Patch_CreateThread_ByStartAddress(uintptr_t funcAddr, uintptr_t targetStartAddress)
	{
		size_t funcSize = GetFunctionSizeByRetn(funcAddr);
		if (!funcSize) return false;

		auto code = reinterpret_cast<uint8_t*>(funcAddr);
		int patched = 0;

		for (size_t i = 0; i + 40 < funcSize; ++i) {
			if (code[i] == 0xC7 && code[i + 1] == 0x44 && code[i + 2] == 0x24 && code[i + 3] == 0x08) {
				uint32_t paramAddr = *reinterpret_cast<uint32_t*>(&code[i + 4]);
				for (size_t k = 4; k <= 40; ++k) {
					if (code[i + k] == 0xE8) {
						if (paramAddr == targetStartAddress) {
							DWORD oldProtect;
							if (VirtualProtect(&code[i + k], 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
								memset(&code[i + k], 0x90, 5);
								VirtualProtect(&code[i + k], 5, oldProtect, &oldProtect);
								++patched;
							}
						}
						break;
					}
				}
			}
		}
		return patched > 0;
	}

	static bool Init_CreateThreadPatch()
	{
		uintptr_t funcAddr = Get_CreateThreadFunction();
		if (!funcAddr) return false;

		PrepareThreadSigs();
		int patchedCount = 0;

		for (auto& sig : g_threadSigs) {
			if (sig.resolvedAddress == 0) continue;
			if (Patch_CreateThread_ByStartAddress(funcAddr, sig.resolvedAddress))
				patchedCount++;
		}
		te::sdk::helper::logging::Log("[#TE FZ] Patched %d/%zu CreateThread calls",
			patchedCount, g_threadSigs.size());
		return patchedCount == static_cast<int>(g_threadSigs.size());
	}

	// Simulate VirtualProtect patch at 0x6E2E50
	static bool SimulateVirtualProtectPatch()
	{
		auto addr = reinterpret_cast<BYTE*>(0x6E2E50);
		DWORD oldProtect;

		if (!VirtualProtect(addr, 3, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		*(WORD*)&addr[0] = 0x1CC2;
		addr[2] = 0x00;
		VirtualProtect(addr, 3, oldProtect, &oldProtect);

		te::sdk::helper::logging::Log("[#TE FZ] VirtualProtect patch at 0x6E2E50 applied");
		return true;
	}

	// ---------- Find & Hook FZ Functions ----------

	// Make memory page executable (needed for MinHook on RW pages)
	static bool EnsureExecutable(uintptr_t addr)
	{
		DWORD oldProtect;
		if (VirtualProtect(reinterpret_cast<LPVOID>(addr), 64, PAGE_EXECUTE_READWRITE, &oldProtect)) {
			return true;
		}
		te::sdk::helper::logging::Log("[#TE FZ] VirtualProtect failed for 0x%08X, error=%d", addr, GetLastError());
		return false;
	}

	static void LogRegionInfo(const char* label, uintptr_t addr)
	{
		MEMORY_BASIC_INFORMATION mbi;
		auto vq = o_VirtualQuery ? o_VirtualQuery : VirtualQuery;
		if (vq(reinterpret_cast<void*>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
			const char* typeStr = (mbi.Type == MEM_PRIVATE) ? "PRIV" : (mbi.Type == MEM_IMAGE) ? "IMG" : "MAP";
			te::sdk::helper::logging::Log("[#TE FZ]   %s 0x%08X -> region 0x%08X +0x%X %s prot=0x%02X state=0x%X",
				label, addr, (uint32_t)reinterpret_cast<uintptr_t>(mbi.BaseAddress),
				(uint32_t)mbi.RegionSize, typeStr, mbi.Protect, mbi.State);
		}
	}

	// ---------- Delayed Scanner Thread ----------

	// Persistent list of FZ code regions (copied from VP hook data)
	static std::vector<ExecPage> g_fzCodeRegions;
	static bool g_fzRegionsAnalyzed = false;
	static uintptr_t g_chatPushCandidate = 0;

	// ---------- Export Table Based Hooking ----------
	// FZ DLL has named exports (SendCommand, rsmbxrvbtfgl@4, etc.) that we can resolve at runtime.
	// @4 suffix = 4 bytes stack cleanup = 1 __stdcall param → ChatPush candidate
	// This is more reliable than signature scanning since it doesn't depend on obfuscation patterns.

	struct FZExportInfo {
		uintptr_t sendCommand = 0;
		uintptr_t chatPush = 0;      // @4 decorated export (1 param __stdcall)
		uintptr_t close16 = 0;       // Obfuscated @16 export (TIMERPROC callback)
		std::string chatPushName;
		std::string close16Name;
		int totalExports = 0;
	};

	static std::unordered_set<uintptr_t> g_analyzedBases;
	static FZExportInfo g_fzExports;

	// SEH-protected: find PE module base by walking back from an executable page
	extern "C" uintptr_t __stdcall FindFZModuleBase_SEH(uintptr_t execPageAddr)
	{
		__try {
			uintptr_t pageBase = execPageAddr & ~0xFFFUL;

			// Walk backwards up to 16 pages looking for MZ header
			for (int i = 0; i <= 16; i++) {
				uintptr_t testBase = pageBase - (i * 0x1000);
				if (testBase < 0x10000) break;

				auto p = reinterpret_cast<const uint8_t*>(testBase);
				if (p[0] != 0x4D || p[1] != 0x5A) continue;

				uint32_t peOff = *reinterpret_cast<const uint32_t*>(testBase + 0x3C);
				if (peOff == 0 || peOff > 0x1000) continue;

				if (*reinterpret_cast<const uint32_t*>(testBase + peOff) == 0x00004550) {
					return testBase;
				}
			}
			return 0;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return 0;
		}
	}

	// Raw C-style result from SEH-protected export parsing (no C++ objects in __try)
	struct FZExportRaw {
		uintptr_t sendCommand;
		uintptr_t chatPush;
		uintptr_t close16;
		char chatPushName[128];
		char close16Name[128];
		int totalExports;
		// Log buffer: up to 64 exports, each line stored for post-SEH logging
		struct { char name[128]; uintptr_t addr; uint32_t rva; } entries[64];
		int entryCount;
	};

	// SEH-protected: parse PE export table into raw C struct
	extern "C" BOOL __stdcall ResolveFZExports_Raw_SEH(uintptr_t base, FZExportRaw* raw)
	{
		__try {
			memset(raw, 0, sizeof(*raw));

			uint32_t peOff = *reinterpret_cast<const uint32_t*>(base + 0x3C);

			uint32_t exportRVA = *reinterpret_cast<const uint32_t*>(base + peOff + 0x78);
			uint32_t exportSz  = *reinterpret_cast<const uint32_t*>(base + peOff + 0x7C);
			if (exportRVA == 0 || exportSz == 0) return FALSE;

			uintptr_t exportDir = base + exportRVA;

			uint32_t numFunctions  = *reinterpret_cast<const uint32_t*>(exportDir + 0x14);
			uint32_t numNames      = *reinterpret_cast<const uint32_t*>(exportDir + 0x18);
			uint32_t addrFunctions = *reinterpret_cast<const uint32_t*>(exportDir + 0x1C);
			uint32_t addrNames     = *reinterpret_cast<const uint32_t*>(exportDir + 0x20);
			uint32_t addrOrdinals  = *reinterpret_cast<const uint32_t*>(exportDir + 0x24);

			if (numNames == 0 || numNames > 500) return FALSE;
			raw->totalExports = (int)numNames;

			for (uint32_t i = 0; i < numNames; i++) {
				uint32_t nameRVA = *reinterpret_cast<const uint32_t*>(base + addrNames + i * 4);
				auto namePtr = reinterpret_cast<const char*>(base + nameRVA);

				char name[128] = {};
				for (int j = 0; j < 127; j++) {
					name[j] = namePtr[j];
					if (name[j] == '\0') break;
				}

				uint16_t ordinal = *reinterpret_cast<const uint16_t*>(base + addrOrdinals + i * 2);
				uint32_t funcRVA = *reinterpret_cast<const uint32_t*>(base + addrFunctions + ordinal * 4);

				if (funcRVA >= exportRVA && funcRVA < exportRVA + exportSz) continue;

				uintptr_t funcAddr = base + funcRVA;

				// Store for logging after SEH block
				if (raw->entryCount < 64) {
					strncpy(raw->entries[raw->entryCount].name, name, 127);
					raw->entries[raw->entryCount].addr = funcAddr;
					raw->entries[raw->entryCount].rva = funcRVA;
					raw->entryCount++;
				}

				// Match SendCommand
				if (strcmp(name, "SendCommand") == 0) {
					raw->sendCommand = funcAddr;
				}

				// Find @N suffix using C string ops
				const char* atSign = strchr(name, '@');
				if (atSign && atSign > name) {
					size_t prefixLen = atSign - name;

					// Skip known cheat feature exports
					if ((prefixLen == 8 && strncmp(name, "FastSkin", 8) == 0) ||
						(prefixLen == 8 && strncmp(name, "Patinaje", 8) == 0))
						continue;

					if (strcmp(atSign, "@4") == 0) {
						raw->chatPush = funcAddr;
						strncpy(raw->chatPushName, name, 127);
					}
					else if (strcmp(atSign, "@16") == 0) {
						raw->close16 = funcAddr;
						strncpy(raw->close16Name, name, 127);
					}
				}
			}

			return (raw->sendCommand || raw->chatPush) ? TRUE : FALSE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	// C++ wrapper: parses exports and populates FZExportInfo (with std::string members)
	static bool ResolveFZExports(uintptr_t base, FZExportInfo* info)
	{
		FZExportRaw raw;
		if (!ResolveFZExports_Raw_SEH(base, &raw)) return false;

		info->sendCommand = raw.sendCommand;
		info->chatPush = raw.chatPush;
		info->close16 = raw.close16;
		info->chatPushName = raw.chatPushName;
		info->close16Name = raw.close16Name;
		info->totalExports = raw.totalExports;

		return info->sendCommand != 0 || info->chatPush != 0;
	}

	// SEH-protected: check if code at address is present (not zeroes)
	// Also recognizes JMP trampolines (E9/FF25) as valid code
	extern "C" BOOL __stdcall IsCodeReady_SEH(uintptr_t addr)
	{
		__try {
			auto p = reinterpret_cast<const uint8_t*>(addr);

			// All zeros = not yet decompressed
			int zeroCount = 0;
			for (int i = 0; i < 16; i++) {
				if (p[i] == 0x00) zeroCount++;
			}
			if (zeroCount >= 14) return FALSE;

			// JMP trampoline = code is present (export stub redirecting to .Jz?)
			if (p[0] == 0xE9) return TRUE;
			if (p[0] == 0xFF && p[1] == 0x25) return TRUE;

			// Function prologue (push ebp, possibly with obfuscation junk before mov ebp, esp)
			for (int i = 0; i < 4; i++) {
				if (p[i] == 0x55) return TRUE;
			}

			// Count valid x86 opcodes
			int validOpcodes = 0;
			for (int i = 0; i < 16; i++) {
				if (p[i] == 0x55 || p[i] == 0x89 || p[i] == 0x8B || p[i] == 0x83 ||
					p[i] == 0xE8 || p[i] == 0xE9 || p[i] == 0xC3 || p[i] == 0x53 ||
					p[i] == 0x56 || p[i] == 0x57 || p[i] == 0x50 || p[i] == 0x51) {
					validOpcodes++;
				}
			}
			return (validOpcodes >= 3) ? TRUE : FALSE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	// SEH-protected: follow JMP chains from export stub to real function address
	// Handles: E9 rel32 (jmp near), FF 25 addr32 (jmp [indirect])
	extern "C" uintptr_t __stdcall FollowJmpChain_SEH(uintptr_t addr, int maxDepth)
	{
		__try {
			for (int depth = 0; depth < maxDepth; depth++) {
				auto p = reinterpret_cast<const uint8_t*>(addr);

				if (p[0] == 0xE9) {
					int32_t offset = *reinterpret_cast<const int32_t*>(addr + 1);
					addr = addr + 5 + offset;
					continue;
				}
				if (p[0] == 0xFF && p[1] == 0x25) {
					uint32_t targetPtr = *reinterpret_cast<const uint32_t*>(addr + 2);
					addr = *reinterpret_cast<const uintptr_t*>(targetPtr);
					continue;
				}
				break; // not a JMP, this is the real address
			}
			return addr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return 0;
		}
	}

	// SEH-protected: find ChatPush in a code region by behavioral pattern
	// ChatPush signature: push ebp; ..junk..; mov ebp, esp; ...; mov reg, [ebp+8]; ...; cmp byte [reg], 0
	extern "C" uintptr_t __stdcall FindChatPushInRegion_SEH(uintptr_t addr, SIZE_T size)
	{
		__try {
			auto p = reinterpret_cast<const uint8_t*>(addr);

			// Skip IAT thunk regions (FF 25 = jmp [addr])
			if (size >= 2 && p[0] == 0xFF && p[1] == 0x25) return 0;

			// Check if decrypted (need some 0x00 bytes in first 64)
			int zeroCount = 0;
			for (int i = 0; i < 64 && (SIZE_T)i < size; i++) {
				if (p[i] == 0x00) zeroCount++;
			}
			if (zeroCount < 2) return 0; // still encrypted

			int prologueCount = 0;
			uintptr_t chatPushAddr = 0;

			for (size_t i = 0; i + 64 < size; i++) {
				auto code = p + i;
				if (code[0] != 0x55) continue;

				// Check if 89 E5 appears within next 20 bytes (obfuscation window)
				int movEbpEspOffset = -1;
				for (int k = 1; k < 20 && (i + k + 1) < size; k++) {
					if (code[k] == 0x89 && code[k + 1] == 0xE5) {
						movEbpEspOffset = k;
						break;
					}
				}
				if (movEbpEspOffset < 0) continue;

				// Log hex dump
				char hex[128] = {};
				size_t pos = 0;
				for (int j = 0; j < 32 && pos + 3 < sizeof(hex); j++)
					pos += snprintf(hex + pos, sizeof(hex) - pos, "%02X ", code[j]);
				if (pos > 0) hex[pos - 1] = '\0';

				// Check if this function accesses [ebp+8] (first param) within 50 bytes after 89 E5
				int paramReg = -1; // 0=eax, 1=ecx, 2=edx
				bool hasSecondParam = false;
				for (int k = movEbpEspOffset + 2; k < movEbpEspOffset + 50 && (i + k + 2) < size; k++) {
					// 8B 45 08 = mov eax, [ebp+8]
					// 8B 4D 08 = mov ecx, [ebp+8]
					// 8B 55 08 = mov edx, [ebp+8]
					if (code[k] == 0x8B && (code[k+1] == 0x45 || code[k+1] == 0x4D || code[k+1] == 0x55) && code[k+2] == 0x08) {
						if (paramReg < 0) {
							paramReg = (code[k+1] == 0x45) ? 0 : (code[k+1] == 0x4D) ? 1 : 2;
						}
					}
					// Check for second param access [ebp+0xC]
					if (code[k] == 0x8B && (code[k+1] == 0x45 || code[k+1] == 0x4D || code[k+1] == 0x55) && code[k+2] == 0x0C) {
						hasSecondParam = true;
					}
				}

				// Look for string null check: cmp byte [reg], 0 (80 39 00, 80 38 00, 80 3A 00)
				// or movsx eax, byte [reg] (0F BE 02, 0F BE 01, 0F BE 00)
				bool hasStringCheck = false;
				if (paramReg >= 0) {
					for (int k = movEbpEspOffset + 2; k < movEbpEspOffset + 80 && (i + k + 2) < size; k++) {
						// cmp byte [ecx], 0 = 80 39 00
						// cmp byte [eax], 0 = 80 38 00
						// cmp byte [edx], 0 = 80 3A 00
						if (code[k] == 0x80 && (code[k+1] == 0x38 || code[k+1] == 0x39 || code[k+1] == 0x3A) && code[k+2] == 0x00) {
							hasStringCheck = true;
							break;
						}
						// movsx eax, byte [edx] = 0F BE 02
						// movsx eax, byte [ecx] = 0F BE 01
						if (code[k] == 0x0F && code[k+1] == 0xBE && (code[k+2] == 0x01 || code[k+2] == 0x02)) {
							hasStringCheck = true;
							break;
						}
					}
				}

				const char* tag = "";
				if (paramReg >= 0 && hasStringCheck && !hasSecondParam) {
					tag = " [CHAT_PUSH?]";
					if (!chatPushAddr) chatPushAddr = addr + i;
				}
				else if (paramReg >= 0 && !hasSecondParam) {
					tag = " [1-param]";
				}
				else if (hasSecondParam) {
					tag = " [multi-param]";
				}

				te::sdk::helper::logging::Log("[#TE FZ] Func #%d at 0x%08X (+0x%X): %s%s",
					prologueCount, (uint32_t)(addr + i), (uint32_t)i, hex, tag);
				prologueCount++;
				if (prologueCount >= 30) break;
			}

			te::sdk::helper::logging::Log("[#TE FZ] Found %d prologues in 0x%08X +0x%X",
				prologueCount, (uint32_t)addr, (uint32_t)size);
			return chatPushAddr;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			te::sdk::helper::logging::Log("[#TE FZ] SEH exception analyzing 0x%08X", (uint32_t)addr);
			return 0;
		}
	}

	// Hook ChatPush directly at the found address
	static bool HookChatPushAt(uintptr_t addr)
	{
		EnsureExecutable(addr);
		MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(addr),
			reinterpret_cast<LPVOID>(Hooked_ChatPush), reinterpret_cast<LPVOID*>(&o_FZ_ChatPush));
		if (s != MH_OK) {
			te::sdk::helper::logging::Log("[#TE FZ] CHAT_PUSH CreateHook failed: %s", MH_StatusToString(s));
			return false;
		}
		MH_STATUS e = MH_EnableHook(reinterpret_cast<LPVOID>(addr));
		if (e != MH_OK) {
			te::sdk::helper::logging::Log("[#TE FZ] CHAT_PUSH EnableHook failed: %s", MH_StatusToString(e));
			MH_RemoveHook(reinterpret_cast<LPVOID>(addr));
			return false;
		}
		te::sdk::helper::logging::Log("[#TE FZ] CHAT_PUSH hooked at 0x%08X", (uint32_t)addr);
		return true;
	}

	static bool HookSendCommandAt(uintptr_t addr)
	{
		EnsureExecutable(addr);
		MH_STATUS s = MH_CreateHook(reinterpret_cast<LPVOID>(addr),
			reinterpret_cast<LPVOID>(Hooked_SendCommand), reinterpret_cast<LPVOID*>(&o_FZ_SendCommand));
		if (s != MH_OK) {
			te::sdk::helper::logging::Log("[#TE FZ] SendCommand CreateHook failed: %s", MH_StatusToString(s));
			return false;
		}
		MH_STATUS e = MH_EnableHook(reinterpret_cast<LPVOID>(addr));
		if (e != MH_OK) {
			te::sdk::helper::logging::Log("[#TE FZ] SendCommand EnableHook failed: %s", MH_StatusToString(e));
			MH_RemoveHook(reinterpret_cast<LPVOID>(addr));
			return false;
		}
		te::sdk::helper::logging::Log("[#TE FZ] SendCommand hooked at 0x%08X", (uint32_t)addr);
		return true;
	}

	static void DelayedFZScanner()
	{
		const int maxAttempts = 40;
		const int intervalMs = 1500;

		te::sdk::helper::logging::Log("[#TE FZ] Delayed scanner started (polling every %dms, max %d attempts)",
			intervalMs, maxAttempts);

		for (int attempt = 1; attempt <= maxAttempts; attempt++)
		{
			Sleep(intervalMs);

			// Collect new VP-detected exec pages into persistent list
			{
				std::lock_guard<std::mutex> lock(g_execPagesMutex);
				if (!g_newExecPages.empty()) {
					//te::sdk::helper::logging::Log("[#TE FZ] [%d] %zu new exec pages:", attempt, g_newExecPages.size());
					for (auto& ep : g_newExecPages) {
						/*te::sdk::helper::logging::Log("[#TE FZ]   0x%08X +0x%X prot=0x%02X",
							(uint32_t)ep.addr, (uint32_t)ep.size, ep.newProt);*/
						g_fzCodeRegions.push_back(ep);
					}
					g_newExecPages.clear();
				}
			}

			// ===== PRIMARY: Export table based hooking =====
			// Find PE module bases from VP-detected exec pages, parse their export tables,
			// and hook FZ functions directly by export name (no signatures needed).

			if (g_fzModuleBase == 0 && !g_fzCodeRegions.empty()) {
				for (auto& region : g_fzCodeRegions) {
					uintptr_t base = FindFZModuleBase_SEH(region.addr);
					if (base == 0 || g_analyzedBases.count(base)) continue;
					g_analyzedBases.insert(base);

					//te::sdk::helper::logging::Log("[#TE FZ] Found PE base 0x%08X from exec page 0x%08X",
					//	(uint32_t)base, (uint32_t)region.addr);

					FZExportInfo info;
					if (ResolveFZExports(base, &info)) {
						//te::sdk::helper::logging::Log("[#TE FZ] Exports: %d total, SendCommand=0x%08X, ChatPush(%s)=0x%08X, Close16(%s)=0x%08X",
						//	info.totalExports, (uint32_t)info.sendCommand,
						//	info.chatPushName.c_str(), (uint32_t)info.chatPush,
						//	info.close16Name.c_str(), (uint32_t)info.close16);

						// Verify FZ module by checking for known exports + reasonable count
						if (info.sendCommand && info.totalExports > 10) {
							g_fzModuleBase = base;
							g_fzModuleSize = GetPESizeOfImage_SEH(base);
							g_fzExports = info;
							te::sdk::helper::logging::Log("[#TE FZ] FenixZone module confirmed at 0x%08X size=0x%X (%d exports)",
								(uint32_t)base, (uint32_t)g_fzModuleSize, info.totalExports);
							break;
						}
					}
					else {
						te::sdk::helper::logging::Log("[#TE FZ] No FZ exports at base 0x%08X", (uint32_t)base);
					}
				}
			}

			// If FZ module found, wait for MPRESS decompression then hook SendCommand
			if (g_fzModuleBase != 0 && !g_fzInternalHooked) {
				uintptr_t sendCmdAddr = g_fzExports.sendCommand;

				if (sendCmdAddr && IsCodeReady_SEH(sendCmdAddr)) {
					// Follow JMP chains: export stub in .text may redirect to real code in .Jz?
					uintptr_t hookTarget = FollowJmpChain_SEH(sendCmdAddr, 5);
					if (hookTarget && hookTarget != sendCmdAddr) {
						te::sdk::helper::logging::Log("[#TE FZ] SendCommand 0x%08X -> JMP chain -> 0x%08X",
							(uint32_t)sendCmdAddr, (uint32_t)hookTarget);
					}
					else {
						hookTarget = sendCmdAddr;
					}

					/*char hex[128] = {};
					HexDumpRegion_SEH(hookTarget, hex, sizeof(hex));
					te::sdk::helper::logging::Log("[#TE FZ] SendCommand at 0x%08X: %s", (uint32_t)hookTarget, hex);*/

					if (HookSendCommandAt(hookTarget)) {
						g_fzInternalHooked = true;

						te::sdk::helper::logging::Log("[#TE FZ] FenixZone bypassed successfully (export-based)!");
						te::sdk::helper::samp::AddChatMessage(
							"[#TE] FenixZone Anti-Cheat bypassed successfully !",
							D3DCOLOR_XRGB(128, 235, 52));
						return;
					}
				}
				else if (sendCmdAddr) {
					char hex[128] = {};
					HexDumpRegion_SEH(sendCmdAddr, hex, sizeof(hex));
					te::sdk::helper::logging::Log("[#TE FZ] [%d] Waiting at SendCommand 0x%08X: %s",
						attempt, (uint32_t)sendCmdAddr, hex);
				}
			}

			// ===== FALLBACK 1: Behavioral analysis (from attempt 5) =====
			if (!g_fzRegionsAnalyzed && attempt >= 5 && attempt <= 15
				&& !g_fzCodeRegions.empty() && !g_fzInternalHooked)
			{
				for (auto& region : g_fzCodeRegions) {
					uintptr_t candidate = FindChatPushInRegion_SEH(region.addr, region.size);
					if (candidate && !g_chatPushCandidate) {
						g_chatPushCandidate = candidate;
						g_fzRegionsAnalyzed = true;
						break;
					}
				}
				if (attempt >= 10) g_fzRegionsAnalyzed = true;
			}

			if (g_chatPushCandidate && !g_fzInternalHooked) {
				te::sdk::helper::logging::Log("[#TE FZ] Behavioral ChatPush candidate at 0x%08X (attempt %d)",
					(uint32_t)g_chatPushCandidate, attempt);
				if (HookChatPushAt(g_chatPushCandidate)) {
					g_fzInternalHooked = true;
					te::sdk::helper::logging::Log("[#TE FZ] FenixZone bypassed (behavioral analysis)!");
					te::sdk::helper::samp::AddChatMessage(
						"[#TE] FenixZone Anti-Cheat bypassed !",
						D3DCOLOR_XRGB(128, 235, 52));
					return;
				}
				g_chatPushCandidate = 0;
			}

			if (attempt % 10 == 0)
				te::sdk::helper::logging::Log("[#TE FZ] Attempt %d/%d: still searching...", attempt, maxAttempts);
		}

		te::sdk::helper::logging::Log("[#TE FZ] Scanner timed out after %d attempts", maxAttempts);
		te::sdk::helper::samp::AddChatMessage(
			"[#TE] FZ bypass: scanner timed out",
			D3DCOLOR_XRGB(255, 165, 0));
	}

	// ---------- PE Scanner with FenixZone Identification ----------

	// Returns: 0 = no PE found, 1 = unknown PE blocked, 2 = FZ PE (allow through, delayed scanner active)
	int ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName)
	{
		try
		{
			int originalOffset = bs->GetReadOffset();
			size_t totalBytes = bs->GetNumberOfBytesUsed();
			std::vector<unsigned char> allData(totalBytes);

			bs->SetReadOffset(0);
			bs->Read(reinterpret_cast<char*>(allData.data()), totalBytes);
			bs->SetReadOffset(originalOffset);

			// Search for MZ header
			size_t mzOffset = 0;
			bool foundMZ = false;
			for (size_t i = 0; i < allData.size() - 1; i++) {
				if (allData[i] == 0x4D && allData[i + 1] == 0x5A) {
					foundMZ = true;
					mzOffset = i;
					break;
				}
			}
			if (!foundMZ) return 0;

			// Verify PE signature
			if (mzOffset + 0x40 >= allData.size()) return 0;
			uint32_t peOffset = 0;
			if (mzOffset + 0x3C + sizeof(uint32_t) <= allData.size())
				peOffset = *reinterpret_cast<uint32_t*>(&allData[mzOffset + 0x3C]);

			bool isPEFile = false;
			if (mzOffset + peOffset + 4 <= allData.size()) {
				isPEFile = (allData[mzOffset + peOffset] == 'P' &&
					allData[mzOffset + peOffset + 1] == 'E' &&
					allData[mzOffset + peOffset + 2] == 0 &&
					allData[mzOffset + peOffset + 3] == 0);
			}
			if (!isPEFile) return 0;

			std::vector<unsigned char> exeData(allData.begin() + mzOffset, allData.end());

			// --- FenixZone identification ---
			int fzScore = IdentifyFenixZone(exeData);

			te::sdk::helper::logging::Log("[#TE] PE detected in RPC %d (%s), size: %zu bytes, FZ score: %d",
				rpcId, rpcName.c_str(), exeData.size(), fzScore);

			if (fzScore < 30) {
				return 1; // Block unknown PE
			}

			te::sdk::helper::logging::Log("[#TE] FenixZone Anti-Cheat identified (score: %d)", fzScore);

			// Install anti-detection hooks on first FZ detection
			if (!g_hooksInitialized) {
				if (!InstallAntiDetectionHooks()) {
					te::sdk::helper::logging::Log("[#TE] Failed to install anti-detection hooks");
				}
			}

			// Start delayed scanner thread on first detection
			if (!g_scannerStarted) {
				g_scannerStarted = true;
				std::thread(DelayedFZScanner).detach();
			}

			return 2; // Allow through - FZ PE, delayed scanner will hook after loading completes
		}
		catch (const std::exception& e)
		{
			te::sdk::helper::logging::Log("[#TE] Exception in ScanForPEExecutable: %s", e.what());
			return 0;
		}
	}
}
