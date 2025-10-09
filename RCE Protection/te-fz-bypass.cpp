#define NOMINMAX 

#include "te-fz-bypass.h"
#include "te-rce-protection.h"

#include <d3d9.h>
#include <vector>
#include <string>
#include <regex>
#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <psapi.h>

#include "Detours/detours_x86.h"
#pragma comment(lib, "Detours/detours_x86.lib")

// Add these definitions to fix compilation errors
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#endif

#ifndef PROCESSINFOCLASS
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdtInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessResourceManagement = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40,
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	MaxProcessInfoClass
} PROCESSINFOCLASS;
#endif

//enum class FenixZoneCommType : uint16_t
//{
//	HARDWARE_INFORMATION = 10000,			// CPU, GPU, RAM, etc.
//	DETECTED_FILES = 20000,					// .ASI, .SF, .CS, ...
//	OPENED_WINDOW_HANDLES = 40000,			// CLASSES, ..
//	PERIODIC_UNKNOWN_INFORMATION = 50000	// Used every +- 2 seconds - hex values (length from 27 to 33); Caller: Unknown
//};

namespace te::rce::fz::bypass
{
	// ---------- Anti-Detection System ----------
	struct HookedFunction {
		FARPROC original;
		FARPROC replacement;
		std::vector<uint8_t> originalBytes;
		std::string moduleName;
		std::string functionName;
		bool isActive;
	};

	static std::vector<HookedFunction> g_hookedFunctions;
	static std::unordered_set<uintptr_t> g_protectedRegions;
	static std::unordered_map<std::string, HMODULE> g_hiddenModules;
	static std::recursive_mutex g_antiDetectionMutex;
	static std::unordered_map<std::string, FARPROC> g_originalFunctions;
	static bool g_hooksInitialized = false;

	// Thread-local recursion guards
	thread_local bool g_inVirtualQuery = false;
	thread_local bool g_inReadProcessMemory = false;

	static PVOID g_vectoredHandler = nullptr;

	// Memory region tracking for clean reads
	struct MemoryRegion {
		uintptr_t start;
		uintptr_t end;
		std::vector<uint8_t> originalData;
		DWORD originalProtect;
	};
	static std::vector<MemoryRegion> g_memoryRegions;

	// Type definitions for function pointers
	typedef NTSTATUS(WINAPI* NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(
		HANDLE ProcessHandle,
		PVOID BaseAddress,
		PVOID Buffer,
		SIZE_T NumberOfBytesToRead,
		PSIZE_T NumberOfBytesRead
		);

	// Helper template to get original function with proper type casting
	template<typename T>
	inline T GetOriginalFunction(const char* name) {
		auto it = g_originalFunctions.find(name);
		return (it != g_originalFunctions.end()) ? reinterpret_cast<T>(it->second) : nullptr;
	}

	// Safe memory copy function - moved to C-style to allow SEH
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

	// C++ wrapper
	bool SafeMemoryCopy(void* dest, const void* src, size_t size) {
		return SafeMemoryCopy_Internal(dest, src, size) == TRUE;
	}

	// Hook for VirtualQuery - masks memory modifications
	extern "C" SIZE_T __stdcall VirtualQuery_SEH_Wrapper(
		decltype(&VirtualQuery) pOriginal,
		LPCVOID lpAddress,
		PMEMORY_BASIC_INFORMATION lpBuffer,
		SIZE_T dwLength)
	{
		__try {
			return pOriginal(lpAddress, lpBuffer, dwLength);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			te::sdk::helper::logging::Log("[#TE] DEBUG: VirtualQuery exception at %p", lpAddress);
			return 0;
		}
	}

	// Helper function to check if filename has suspicious extension
	static bool HasSuspiciousExtension(const std::string& filename) {
		// Find last dot for extension
		size_t dotPos = filename.find_last_of('.');
		if (dotPos == std::string::npos || dotPos == filename.length() - 1) {
			return false; // No extension or dot at end
		}

		std::string ext = filename.substr(dotPos);

		// *** ONLY hide these specific extensions ***
		static const std::vector<std::string> hiddenExtensions = {
			".asi", ".cs", ".sf", ".dll", ".exe", ".lua", ".ifp"
		};

		for (const auto& hiddenExt : hiddenExtensions) {
			if (ext == hiddenExt) {
				return true;
			}
		}

		return false;
	}

	// Helper to check if address belongs to a module with suspicious extension
	static bool IsAddressInSuspiciousModule(LPCVOID lpAddress) {
		HMODULE hModule = NULL;

		// Get module handle for this address - use direct Windows API to avoid recursion
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
			GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(lpAddress), &hModule)) {
			return false; // Not in any module
		}

		char modulePath[MAX_PATH] = { 0 };
		if (!GetModuleFileNameA(hModule, modulePath, MAX_PATH)) {
			return false;
		}

		std::string modPath(modulePath);
		std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);

		// Extract filename
		size_t lastSlash = modPath.find_last_of("\\/");
		std::string modName = (lastSlash != std::string::npos) ?
			modPath.substr(lastSlash + 1) : modPath;

		// Check if module has suspicious extension
		return HasSuspiciousExtension(modName);
	}

	// Hook for VirtualQuery - masks memory modifications (ENHANCED)
	SIZE_T WINAPI Hooked_VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
	{
		auto pOriginal = GetOriginalFunction<decltype(&VirtualQuery)>("VirtualQuery");
		if (!pOriginal) {
			return 0;
		}

		if (g_inVirtualQuery) {
			return pOriginal(lpAddress, lpBuffer, dwLength);
		}

		bool isSuspiciousModule = IsAddressInSuspiciousModule(lpAddress);

		g_inVirtualQuery = true;
		SIZE_T result = pOriginal(lpAddress, lpBuffer, dwLength);

		if (isSuspiciousModule) {
			g_inVirtualQuery = false;
			SetLastError(ERROR_INVALID_PARAMETER); // Fake error
			return 0;
		}

		if (result && lpBuffer && !g_memoryRegions.empty()) {
			uintptr_t addr = reinterpret_cast<uintptr_t>(lpAddress);

			size_t maxCheck = std::min(g_memoryRegions.size(), size_t(10));

			for (size_t i = maxCheck; i > 0; --i) {
				const auto& region = g_memoryRegions[i - 1];

				if (addr >= region.start && addr < region.end) {
					// Restore original protection flags to hide modifications
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

	extern "C" BOOL __stdcall CheckMemoryRegions_SEH(
		uintptr_t addr,
		LPVOID lpBuffer,
		SIZE_T nSize,
		SIZE_T* lpNumberOfBytesRead,
		const std::vector<HookedFunction>* pHooks,
		const std::vector<MemoryRegion>* pRegions)
	{
		__try {
			size_t maxHooks = std::min(pHooks->size(), size_t(10)); // Limit to 10 most recent
			for (size_t i = maxHooks; i > 0; --i) {
				const auto& hook = (*pHooks)[i - 1];
				if (!hook.isActive) continue;

				uintptr_t hookAddr = reinterpret_cast<uintptr_t>(hook.original);
				uintptr_t hookEnd = hookAddr + hook.originalBytes.size();

				if (addr >= hookAddr && addr < hookEnd) {
					size_t offset = addr - hookAddr;
					size_t copySize = std::min(static_cast<size_t>(nSize),
						hook.originalBytes.size() - offset);
					memcpy(lpBuffer, hook.originalBytes.data() + offset, copySize);
					if (lpNumberOfBytesRead) *lpNumberOfBytesRead = copySize;
					return TRUE;
				}
			}

			size_t maxRegions = std::min(pRegions->size(), size_t(10)); // Limit to 10 most recent
			for (size_t i = maxRegions; i > 0; --i) {
				const auto& region = (*pRegions)[i - 1];

				if (addr >= region.start && addr < region.end) {
					size_t offset = addr - region.start;
					size_t copySize = std::min(static_cast<size_t>(nSize),
						region.originalData.size() - offset);
					memcpy(lpBuffer, region.originalData.data() + offset, copySize);
					if (lpNumberOfBytesRead) *lpNumberOfBytesRead = copySize;
					return TRUE;
				}
			}

			return FALSE; // Not found in any region
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return -1; // Error indicator
		}
	}

	// Hook for ReadProcessMemory - returns clean data (OPTIMIZED)
	BOOL WINAPI Hooked_ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
		LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		auto pOriginal = GetOriginalFunction<decltype(&ReadProcessMemory)>("ReadProcessMemory");
		if (!pOriginal) {
			return FALSE;
		}

		if (g_inReadProcessMemory) {
			return pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		}

		if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
			return pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		}

		g_inReadProcessMemory = true;

		if (g_hookedFunctions.empty() && g_memoryRegions.empty()) {
			BOOL result = pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
			g_inReadProcessMemory = false;
			return result;
		}

		uintptr_t addr = reinterpret_cast<uintptr_t>(lpBaseAddress);

		std::unique_lock<std::recursive_mutex> lock(g_antiDetectionMutex, std::try_to_lock);
		if (!lock.owns_lock()) {
			BOOL result = pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
			g_inReadProcessMemory = false;
			return result;
		}

		BOOL regionResult = CheckMemoryRegions_SEH(addr, lpBuffer, nSize, lpNumberOfBytesRead,
			&g_hookedFunctions, &g_memoryRegions);

		if (regionResult == TRUE) {
			g_inReadProcessMemory = false;
			return TRUE;
		}
		else if (regionResult == -1) {
			g_inReadProcessMemory = false;
			return FALSE;
		}

		BOOL result = pOriginal(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
		g_inReadProcessMemory = false;
		return result;
	}

	// Hook for FindFirstFileA - hides files with suspicious extensions
	HANDLE WINAPI Hooked_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
	{
		auto pOriginal = GetOriginalFunction<decltype(&FindFirstFileA)>("FindFirstFileA");
		if (!pOriginal) return INVALID_HANDLE_VALUE;

		HANDLE result = pOriginal(lpFileName, lpFindFileData);

		if (result != INVALID_HANDLE_VALUE && lpFindFileData) {
			std::string filename(lpFindFileData->cFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

			// *** ONLY check extension, not filename patterns ***
			if (HasSuspiciousExtension(filename)) {
				FindClose(result);
				SetLastError(ERROR_NO_MORE_FILES);
				return INVALID_HANDLE_VALUE;
			}
		}

		return result;
	}

	// Hook for FindNextFileA - continues hiding files with suspicious extensions
	BOOL WINAPI Hooked_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
	{
		auto pOriginal = GetOriginalFunction<decltype(&FindNextFileA)>("FindNextFileA");
		if (!pOriginal) return FALSE;

		BOOL result;
		do {
			result = pOriginal(hFindFile, lpFindFileData);
			if (!result) break;

			std::string filename(lpFindFileData->cFileName);
			std::transform(filename.begin(), filename.end(), filename.begin(), ::tolower);

			// *** ONLY check extension, not filename patterns ***
			if (!HasSuspiciousExtension(filename)) {
				break; // Show this file
			}
			// If has suspicious extension, continue to next file
		} while (result);

		return result;
	}

	// Hook for EnumProcessModules - hides modules with suspicious extensions
	BOOL WINAPI Hooked_EnumProcessModules(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded)
	{
		auto pOriginal = GetOriginalFunction<decltype(&EnumProcessModules)>("EnumProcessModules");
		if (!pOriginal) return FALSE;

		// Only intercept for current process
		if (hProcess != GetCurrentProcess() && hProcess != (HANDLE)-1) {
			return pOriginal(hProcess, lphModule, cb, lpcbNeeded);
		}

		// Try to acquire lock, but don't block - prevent deadlock
		std::unique_lock<std::recursive_mutex> lock(g_antiDetectionMutex, std::try_to_lock);
		if (!lock.owns_lock()) {
			return pOriginal(hProcess, lphModule, cb, lpcbNeeded);
		}

		BOOL result = pOriginal(hProcess, lphModule, cb, lpcbNeeded);

		if (result && lphModule && lpcbNeeded && *lpcbNeeded > 0) {
			// Use direct GetProcAddress to avoid any potential hooks
			auto hKernel32 = ::GetModuleHandleA("kernel32.dll");
			auto pGetModuleFileNameA = reinterpret_cast<decltype(&GetModuleFileNameA)>(
				::GetProcAddress(hKernel32, "GetModuleFileNameA"));

			if (!pGetModuleFileNameA) {
				return result; // Fallback - return unfiltered results
			}

			// Filter out hidden modules
			DWORD moduleCount = cb / sizeof(HMODULE);
			DWORD filteredCount = 0;

			for (DWORD i = 0; i < moduleCount && i < (*lpcbNeeded / sizeof(HMODULE)); i++) {
				char modulePath[MAX_PATH] = { 0 };

				if (pGetModuleFileNameA(lphModule[i], modulePath, MAX_PATH)) {
					std::string modPath(modulePath);
					std::transform(modPath.begin(), modPath.end(), modPath.begin(), ::tolower);

					// Extract just the filename
					size_t lastSlash = modPath.find_last_of("\\/");
					std::string modName = (lastSlash != std::string::npos) ?
						modPath.substr(lastSlash + 1) : modPath;

					bool shouldHide = false;

					// *** ONLY check extension, not filename patterns ***
					if (HasSuspiciousExtension(modName)) {
						shouldHide = true;
					}

					// Also check against explicitly registered hidden modules
					for (const auto& [hiddenName, hiddenModule] : g_hiddenModules) {
						if (lphModule[i] == hiddenModule) {
							shouldHide = true;
							break;
						}
					}

					if (!shouldHide) {
						if (filteredCount != i) {
							lphModule[filteredCount] = lphModule[i];
						}
						filteredCount++;
					}
				}
				else {
					// If we can't get the name, include it to be safe
					if (filteredCount != i) {
						lphModule[filteredCount] = lphModule[i];
					}
					filteredCount++;
				}
			}

			*lpcbNeeded = filteredCount * sizeof(HMODULE);
		}

		return result;
	}

	// Helper functions for SEH operations - no C++ objects
	extern "C" BOOL __stdcall CopyOriginalBytes(void* dest, const void* src, size_t size) {
		__try {
			memcpy(dest, src, size);
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	extern "C" BOOL __stdcall WriteHookJump(void* target, void* replacement) {
		__try {
			uint8_t* pFunc = reinterpret_cast<uint8_t*>(target);
			pFunc[0] = 0xE9; // JMP
			*reinterpret_cast<uint32_t*>(&pFunc[1]) =
				reinterpret_cast<uintptr_t>(replacement) -
				reinterpret_cast<uintptr_t>(target) - 5;

			// Fill rest with NOPs
			for (int i = 5; i < 16; i++) {
				pFunc[i] = 0x90; // NOP
			}
			return TRUE;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			return FALSE;
		}
	}

	// Function to install a single hook with backup
	bool InstallSingleHook(HMODULE hModule, const char* functionName, FARPROC replacement)
	{
		//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing hook for %s using Detours", functionName);

		std::lock_guard<std::recursive_mutex> lock(g_antiDetectionMutex);

		FARPROC original = ::GetProcAddress(hModule, functionName);
		if (!original) {
			te::sdk::helper::logging::Log("[#TE] Failed to find %s", functionName);
			return false;
		}

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Found %s at %p", functionName, original);

		// Store original function pointer BEFORE hooking
		g_originalFunctions[functionName] = original;

		HookedFunction hook;
		hook.original = original;
		hook.replacement = replacement;
		char moduleName[MAX_PATH];
		GetModuleFileNameA(hModule, moduleName, MAX_PATH);
		hook.moduleName = moduleName;
		hook.functionName = functionName;
		hook.isActive = false;

		// Backup original bytes using safe copy
		hook.originalBytes.resize(16);
		if (!CopyOriginalBytes(hook.originalBytes.data(), original, 16)) {
			te::sdk::helper::logging::Log("[#TE] Failed to backup bytes for %s", functionName);
			return false;
		}

		// *** Use Detours API for hooking ***
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		// DetourAttach modifies the pointer - we need a mutable copy
		PVOID pOriginalCopy = original;
		LONG error = DetourAttach(&pOriginalCopy, replacement);

		if (error != NO_ERROR) {
			DetourTransactionAbort();
			te::sdk::helper::logging::Log("[#TE] DetourAttach failed for %s (error: %ld)", functionName, error);
			return false;
		}

		error = DetourTransactionCommit();
		if (error != NO_ERROR) {
			te::sdk::helper::logging::Log("[#TE] DetourTransactionCommit failed for %s (error: %ld)", functionName, error);
			return false;
		}

		// Update original pointer in case Detours modified it (it creates a trampoline)
		g_originalFunctions[functionName] = (FARPROC)pOriginalCopy;

		hook.isActive = true;
		g_hookedFunctions.push_back(hook);

		te::sdk::helper::logging::Log("[#TE] Hooked %s!%s at %p -> %p (Detours)",
			hook.moduleName.c_str(), hook.functionName.c_str(), pOriginalCopy, replacement);

		return true;
	}

	// Forward declarations
	LONG WINAPI HardwareBreakpointHandler(PEXCEPTION_POINTERS pExceptionInfo);
	LONG WINAPI SingleStepRestoreHandler(PEXCEPTION_POINTERS pExceptionInfo);

	// Watched memory addresses
	struct WatchedAddress {
		uintptr_t addr;
		BYTE spoofedValue;
		BYTE realValue;
		std::atomic<size_t> accessCount;

		// Přidat konstruktor pro inicializaci
		WatchedAddress(uintptr_t a, BYTE spoofed, BYTE real)
			: addr(a), spoofedValue(spoofed), realValue(real), accessCount(0) {
		}

		// Delete copy constructor a copy assignment (atomic nelze kopírovat)
		WatchedAddress(const WatchedAddress&) = delete;
		WatchedAddress& operator=(const WatchedAddress&) = delete;

		// Povolit move semantiku
		WatchedAddress(WatchedAddress&& other) noexcept
			: addr(other.addr),
			spoofedValue(other.spoofedValue),
			realValue(other.realValue),
			accessCount(other.accessCount.load()) {
		}

		WatchedAddress& operator=(WatchedAddress&& other) noexcept {
			if (this != &other) {
				addr = other.addr;
				spoofedValue = other.spoofedValue;
				realValue = other.realValue;
				accessCount.store(other.accessCount.load());
			}
			return *this;
		}
	};

	static std::vector<WatchedAddress> g_watchedAddresses;

	void InitializeWatchedAddresses() {
		g_watchedAddresses.clear();
		g_watchedAddresses.emplace_back(0xB7CEE4, 0, 0);    // Infinite run
		g_watchedAddresses.emplace_back(0x96916D, 0, 0);     // Unknown check
	}

	bool InstallAntiDetectionHooks()
	{
		if (g_hooksInitialized) {
			te::sdk::helper::logging::Log("[#TE] Hooks already initialized");
			return true;
		}

		te::sdk::helper::logging::Log("[#TE] Installing comprehensive anti-detection hooks");

		HMODULE hKernel32 = ::GetModuleHandleA("kernel32.dll");
		HMODULE hNtdll = ::GetModuleHandleA("ntdll.dll");
		HMODULE hPsapi = ::LoadLibraryA("psapi.dll");

		if (!hKernel32 || !hNtdll) {
			te::sdk::helper::logging::Log("[#TE] Failed to get required module handles (K32: %p, Ntdll: %p)", hKernel32, hNtdll);
			return false;
		}

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Module handles - Kernel32: %p, Ntdll: %p, Psapi: %p", hKernel32, hNtdll, hPsapi);

		// Store all original functions in the map
		//te::sdk::helper::logging::Log("[#TE] DEBUG: Storing original function pointers");

		g_originalFunctions["VirtualQuery"] = ::GetProcAddress(hKernel32, "VirtualQuery");
		g_originalFunctions["ReadProcessMemory"] = ::GetProcAddress(hKernel32, "ReadProcessMemory");
		g_originalFunctions["VirtualProtect"] = ::GetProcAddress(hKernel32, "VirtualProtect");
		g_originalFunctions["FindFirstFileA"] = ::GetProcAddress(hKernel32, "FindFirstFileA");
		g_originalFunctions["FindNextFileA"] = ::GetProcAddress(hKernel32, "FindNextFileA");
		if (hPsapi) {
			g_originalFunctions["EnumProcessModules"] = ::GetProcAddress(hPsapi, "EnumProcessModules");
		}

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Original functions stored");

		g_hooksInitialized = true;

		bool success = true;

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing VirtualQuery hook");
		success &= InstallSingleHook(hKernel32, "VirtualQuery", reinterpret_cast<FARPROC>(Hooked_VirtualQuery));

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing ReadProcessMemory hook");
		success &= InstallSingleHook(hKernel32, "ReadProcessMemory", reinterpret_cast<FARPROC>(Hooked_ReadProcessMemory));

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing FindFirstFileA hook");
		success &= InstallSingleHook(hKernel32, "FindFirstFileA", reinterpret_cast<FARPROC>(Hooked_FindFirstFileA));

		//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing FindNextFileA hook");
		success &= InstallSingleHook(hKernel32, "FindNextFileA", reinterpret_cast<FARPROC>(Hooked_FindNextFileA));

		if (hPsapi) {
			//te::sdk::helper::logging::Log("[#TE] DEBUG: Installing EnumProcessModules hook");
			success &= InstallSingleHook(hPsapi, "EnumProcessModules", reinterpret_cast<FARPROC>(Hooked_EnumProcessModules));
		}

		if (!success) {
			te::sdk::helper::logging::Log("[#TE] Some hooks failed to install");
			g_hooksInitialized = false;
			return false;
		}

		te::sdk::helper::logging::Log("[#TE] All hooks installed successfully");
		//te::sdk::helper::logging::Log("[#TE] DEBUG: InstallAntiDetectionHooks complete, success: %d", success);

		/*InitializeWatchedAddresses();

		for (const auto& addr : g_watchedAddresses) 
		{
			*reinterpret_cast<BYTE*>(addr.addr) = reinterpret_cast<BYTE>(addr.spoofedValue);
		}*/

		return true;
	}

	// Function to register a module as hidden
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

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		for (auto& hook : g_hookedFunctions) {
			if (!hook.isActive) continue;

			PVOID pCurrent = g_originalFunctions[hook.functionName];

			LONG error = DetourDetach(&pCurrent, hook.replacement);
			if (error == NO_ERROR) {
				hook.isActive = false;
				te::sdk::helper::logging::Log("[#TE] Unhooked %s!%s",
					hook.moduleName.c_str(), hook.functionName.c_str());
			}
			else {
				te::sdk::helper::logging::Log("[#TE] Failed to unhook %s (error: %ld)",
					hook.functionName.c_str(), error);
			}
		}

		DetourTransactionCommit();

		g_hookedFunctions.clear();
		g_memoryRegions.clear();
		g_hiddenModules.clear();
		g_originalFunctions.clear();

		te::sdk::helper::logging::Log("[#TE] All hooks and data cleared");
	}

	// Returns true if a PE executable is detected and should be blocked
	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName)
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

			for (size_t i = 0; i < allData.size() - 1; i++)
			{
				if (allData[i] == 0x4D && allData[i + 1] == 0x5A) // MZ
				{
					foundMZ = true;
					mzOffset = i;
					break;
				}
			}

			if (!foundMZ) {
				te::sdk::helper::logging::Log("[#TE] No PE executable found in RPC %d (%s)",
					rpcId, rpcName.c_str());
				return false;
			}

			// Verify PE signature
			if (mzOffset + 0x40 >= allData.size()) {
				te::sdk::helper::logging::Log("[#TE] Invalid PE structure in RPC %d", rpcId);
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

			if (isPEFile && !g_hooksInitialized) {
				std::vector<unsigned char> exeData(allData.begin() + mzOffset, allData.end());

				te::sdk::helper::logging::Log("[#TE] Detected malicious PE executable in RPC %d (%s), size: %zu bytes",
					rpcId, rpcName.c_str(), exeData.size());

				te::sdk::helper::logging::Log("[#TE] Starting enhanced bypass with anti-detection");

				auto result = InstallAntiDetectionHooks();
				if (result) {
					te::sdk::helper::logging::Log("[#TE] Enhanced bypass initialized successfully");
					te::sdk::helper::samp::AddChatMessage("[#TE] FenixZone Anti-Cheat bypassed via enhanced protection !", D3DCOLOR_XRGB(128, 235, 52));

					return false; // Process
				}
				else {
					te::sdk::helper::logging::Log("[#TE] Failed to initialize enhanced bypass");
				}

				return true; // Block
			}

			return !g_hooksInitialized; // ?
			//return true; // Block
		}
		catch (const std::exception& e)
		{
			te::sdk::helper::logging::Log("[#TE] Exception in ScanForPEExecutable: %s", e.what());

			return false; // Process
		}
	}
}