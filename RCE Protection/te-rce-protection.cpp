#include "te-rce-protection.h"
#include "te-fz-bypass.h"

#include <array>
#include <unordered_map>
#include <cctype>

namespace te::rce::helper
{
	struct ShellcodePattern {
		std::vector<uint8_t> signature;
		std::string description;
	};

	std::vector<RPC> rpcListInBits = {
	{
		84, "SetPlayerObjectMaterial(Text)",
		(sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint8_t)) * 8 + 4096 * 8, // total base size in bits
		{8, 8, 8, 2048 * 8}, // dynamic lengths in bits
		{96, 104, 112, 120}, // offsets in bits
		{false, false, false, true} // indicates if the lengths are fixed
	},

	{
		173, "ApplyActorAnimation",
		(16 + 8 + 8 + 32 + 8 + 8 + 8 + 8 + 32),  // base size in bits (excluding dynamic arrays)
		{8, 8},  // dynamic lengths in bits (AnimLibLength, AnimNameLength)
		{24, 32},  // offsets in bits for dynamic lengths (relative to start of wActorID)
		{false, false}  // dynamic lengths are not fixed
	},

	{
		61, "ShowDialog",
		(16 + 8 + 8 + 8 + 8 + 8 + 32768),  // total base size in bits
		{8, 8, 8},  // dynamic lengths in bits
		{32, 40, 48},  // offsets in bits for dynamic lengths
		{false, false, true}  // dynamic lengths are not fixed
	},

	{
		59, "ChatBubble",
		(16 + 32 + 32 + 32 + 8),  // base size in bits (excluding dynamic array)
		{8},  // dynamic length in bits (textLength)
		{120},  // offset in bits for the dynamic length (relative to the start of playerid)
		{false}  // the length is not fixed
	},

	{
		73, "ShowGameText",
		(32 + 32 + 32),  // base size in bits
		{32},  // dynamic length in bits (dMessageLength)
		{96},  // offset in bits for dynamic length
		{false}  // the length is not fixed
	},

	{
		86, "ApplyPlayerAnimation",
		128,  // base size in bits (excluding dynamic arrays)
		{8, 8},  // dynamic lengths in bits (AnimLibLength, AnimNameLength)
		{16, 24},  // offsets in bits for dynamic lengths (relative to start of wPlayerID)
		{false, false}  // dynamic lengths are not fixed
	}
	};

	// Build a hashmap for O(1) RPC lookup by ID
	static std::unordered_map<int, RPC*> buildRpcMap() {
		std::unordered_map<int, RPC*> map;
		map.reserve(rpcListInBits.size());
		for (auto& rpc : rpcListInBits) {
			map[rpc.id] = &rpc;
		}
		return map;
	}

	static std::unordered_map<int, RPC*> rpcMap = buildRpcMap();

	RPC* findRPCById(int rpcId) {
		auto it = rpcMap.find(rpcId);
		return (it != rpcMap.end()) ? it->second : nullptr;
	}

	// Calculate expected RPC size without copying the RPC struct
	int calcSize(const RPC* rpc, BitStream* bs) {
		int totalSize = rpc->baseSize;

		int currentOffset = rpc->dynamicLengths.size() > 0 ? rpc->dynamicOffsets[0] : 0;

		for (size_t i = 0; i < rpc->dynamicLengths.size(); ++i) {
			if (rpc->isFixedSize[i]) {
				totalSize += rpc->dynamicLengths[i];
			}
			else {
				bs->SetReadOffset(currentOffset);

				int dynamicLengthInBits = 0;

				if (rpc->dynamicLengths[i] == 8) {
					uint8_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}
				else if (rpc->dynamicLengths[i] == 16) {
					uint16_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}
				else if (rpc->dynamicLengths[i] == 32) {
					uint32_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}

				dynamicLengthInBits = dynamicLengthInBits * 8;

				if (dynamicLengthInBits > INT_MAX / 8 || totalSize > INT_MAX - dynamicLengthInBits) {
					return -1;
				}

				totalSize += dynamicLengthInBits;

				if (i < rpc->dynamicOffsets.size() - 1) {
					currentOffset = rpc->dynamicOffsets[i + 1];
					currentOffset += dynamicLengthInBits;
				}
			}
		}

		return totalSize;
	}

	// Unified entropy calculation - works for any contiguous byte range
	template<typename T>
	static double calculateEntropyImpl(const T* data, size_t size) {
		if (size == 0 || size > 1000000)
			return 0.0;

		std::array<int, 256> freq = { 0 };
		for (size_t i = 0; i < size; ++i) {
			freq[static_cast<unsigned char>(data[i])]++;
		}

		double entropy = 0.0;
		for (int f : freq) {
			if (f > 0) {
				double p = static_cast<double>(f) / size;
				entropy -= p * log2(p);
			}
		}
		return entropy;
	}

	double calculateEntropy(const std::vector<unsigned char>& data) {
		return calculateEntropyImpl(data.data(), data.size());
	}

	double calculateEntropy(const std::string& data) {
		return calculateEntropyImpl(data.data(), data.size());
	}

	bool isValidUTF8(const std::vector<unsigned char>& data) {
		int numBytes = 0;
		unsigned char c;

		for (size_t i = 0; i < data.size(); ++i) {
			c = data[i];
			if (numBytes == 0) {
				if ((c >> 5) == 0x06) {
					numBytes = 1;
				}
				else if ((c >> 4) == 0x0E) {
					numBytes = 2;
				}
				else if ((c >> 3) == 0x1E) {
					numBytes = 3;
				}
				else if (c > 0x7F) {
					return false;
				}
			}
			else {
				if ((c >> 6) != 0x02) {
					return false;
				}
				--numBytes;
			}
		}

		return numBytes == 0;
	}

	// Check if character is a valid hex digit (0-9, A-F, a-f)
	static bool isHexChar(unsigned char c) {
		return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
	}

	// Remove SA-MP color codes {XXXXXX} and control characters without regex
	static void stripColorCodesAndControl(const unsigned char* src, size_t srcLen,
		std::vector<unsigned char>& out) {
		out.clear();
		out.reserve(srcLen);

		for (size_t i = 0; i < srcLen; ++i) {
			// Check for SA-MP color code pattern: {XXXXXX}
			if (src[i] == '{' && i + 7 < srcLen && src[i + 7] == '}') {
				bool valid = true;
				for (size_t j = 1; j <= 6; ++j) {
					if (!isHexChar(src[i + j])) {
						valid = false;
						break;
					}
				}
				if (valid) {
					i += 7; // Skip the entire color code
					continue;
				}
			}

			// Skip control characters (\r, \n, \t)
			if (src[i] == '\r' || src[i] == '\n' || src[i] == '\t')
				continue;

			out.push_back(src[i]);
		}
	}

	std::vector<unsigned char> cleanText(const std::vector<unsigned char>& data) {
		std::vector<unsigned char> result;
		stripColorCodesAndControl(data.data(), data.size(), result);
		return result;
	}

	bool isValidText(const std::vector<unsigned char>& data) {
		std::vector<unsigned char> cleanedData = cleanText(data);

		double entropy = calculateEntropy(cleanedData);
		return entropy <= 6.0; // Threshold can be adjusted
	}

	std::string cleanText(const std::string& data) {
		std::vector<unsigned char> result;
		stripColorCodesAndControl(reinterpret_cast<const unsigned char*>(data.data()),
			data.size(), result);
		return std::string(result.begin(), result.end());
	}

	bool isValidText(const std::string& data) {
		std::string cleanedData = cleanText(data);
		double entropy = calculateEntropy(cleanedData);
		return entropy <= 6.0;
	}

	uint32_t PatternScan(uint32_t pModuleBaseAddress, const char* sSignature, bool bSkipFirst)
	{
		auto patternToBytes = [](const char* pattern) -> std::vector<int> {
			std::vector<int> bytes;
			const char* current = pattern;

			while (*current) {
				if (*current == '?') {
					++current;
					if (*current == '?') ++current;
					bytes.push_back(-1);
				}
				else if (isxdigit(*current)) {
					char byteStr[3] = { 0 };
					byteStr[0] = *current++;
					if (isxdigit(*current)) {
						byteStr[1] = *current++;
					}
					bytes.push_back(strtoul(byteStr, nullptr, 16));
				}
				else {
					++current;
				}
			}

			return bytes;
		};

		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pModuleBaseAddress);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		const auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pModuleBaseAddress + dosHeader->e_lfanew);
		if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
			return 0;

		const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		const auto scanBytes = reinterpret_cast<std::uint8_t*>(pModuleBaseAddress);

		const std::vector<int> patternBytes = patternToBytes(sSignature);
		const size_t patternSize = patternBytes.size();
		const int* patternData = patternBytes.data();

		bool foundFirst = false;

		// Cache VirtualQuery results - skip entire invalid regions at once
		size_t regionEnd = 0;
		bool regionValid = false;

		for (size_t i = 0; i <= sizeOfImage - patternSize; ++i)
		{
			// Only call VirtualQuery when we enter a new region
			if (i >= regionEnd) {
				MEMORY_BASIC_INFORMATION mbi;
				if (!VirtualQuery(scanBytes + i, &mbi, sizeof(mbi))) {
					break;
				}

				regionEnd = (reinterpret_cast<size_t>(mbi.BaseAddress) + mbi.RegionSize)
					- reinterpret_cast<size_t>(scanBytes);
				regionValid = (mbi.State == MEM_COMMIT) &&
					(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE));
			}

			// Skip invalid regions entirely
			if (!regionValid) {
				i = regionEnd - 1; // -1 because loop increments
				continue;
			}

			bool found = true;
			for (size_t j = 0; j < patternSize; ++j)
			{
				if (i + j >= sizeOfImage) { found = false; break; }

				if (patternData[j] != -1 && scanBytes[i + j] != static_cast<uint8_t>(patternData[j]))
				{
					found = false;
					break;
				}
			}

			if (found)
			{
				if (bSkipFirst)
				{
					if (!foundFirst)
						foundFirst = true;
					else
						return reinterpret_cast<uint32_t>(&scanBytes[i]);
				}
				else
				{
					return reinterpret_cast<uint32_t>(&scanBytes[i]);
				}
			}
		}

		return 0;
	}

	static const std::vector<ShellcodePattern> SHELLCODE_SIGNATURES = {
		// Common x86 shellcode patterns
		{{0x31, 0xC0}, "XOR EAX, EAX"},
		{{0x50, 0x68}, "PUSH + PUSH (stack setup)"},
		{{0xEB, 0xFE}, "JMP $ (infinite loop)"},
		{{0x90, 0x90, 0x90, 0x90}, "NOP sled"},
		{{0xCC, 0xCC, 0xCC, 0xCC}, "INT3 breakpoint"},
		// Windows API hashing patterns
		{{0x64, 0x8B, 0x25}, "MOV ESP, FS:[offset] (TEB access)"},
		{{0x8B, 0x52, 0x0C}, "MOV EDX, [EDX+0Ch] (PEB traversal)"},
	};

	bool DetectShellcodePatterns(const std::vector<unsigned char>& data) {
		if (data.size() < 4) return false;

		for (const auto& pattern : SHELLCODE_SIGNATURES) {
			for (size_t i = 0; i <= data.size() - pattern.signature.size(); ++i) {
				bool match = true;
				for (size_t j = 0; j < pattern.signature.size(); ++j) {
					if (data[i + j] != pattern.signature[j]) {
						match = false;
						break;
					}
				}
				if (match) {
					te::sdk::helper::logging::Log("[SHELLCODE] Detected pattern: %s at offset %zu",
						pattern.description.c_str(), i);
					return true;
				}
			}
		}

		return false;
	}

	bool DetectSuspiciousInstructions(const std::vector<unsigned char>& data) {
		size_t suspiciousCount = 0;

		for (size_t i = 0; i < data.size() - 1; ++i) {
			// Look for syscall instructions
			if (data[i] == 0x0F && data[i + 1] == 0x05) { // SYSCALL
				suspiciousCount++;
			}
			// Look for interrupt instructions
			else if (data[i] == 0xCD && i + 1 < data.size()) { // INT xx
				suspiciousCount++;
			}
			// Look for call/jmp with register operands (common in shellcode)
			else if ((data[i] == 0xFF) && i + 1 < data.size()) {
				uint8_t modrm = data[i + 1];
				if ((modrm & 0x38) >= 0x10 && (modrm & 0x38) <= 0x28) { // CALL/JMP reg
					suspiciousCount++;
				}
			}
		}

		// If more than 10% of instructions are suspicious
		return (suspiciousCount * 10 > data.size());
	}

	bool CheckRPC(int rpcId, BitStream* bs)
	{
		try
		{
			RPC* rpc = findRPCById(rpcId);
			if (!rpc) {
				return true; // Allow if RPC not found
			}

			auto numberOfBits = bs->GetNumberOfUnreadBits();

			switch (rpcId)
			{
			case 84:
				uint16_t wObjectID;
				uint8_t MaterialType;
				bs->Read(wObjectID);
				bs->Read(MaterialType);

				if (MaterialType == 1)
				{
					uint8_t MaterialIndex;
					bs->Read(MaterialIndex);

					uint16_t ModelID;
					bs->Read(ModelID);

					uint8_t libraryNameLength;
					bs->Read(libraryNameLength);

					std::vector<unsigned char> libraryName(rpc->dynamicLengths[3]);

					if (!bs->ReadCompressed(libraryName.data(), libraryName.size(), true))
					{
						break;
					}

					if (!libraryName.empty() && !isValidText(libraryName)) {
						return false; // Block - invalid text detected
					}
				}
				else if (MaterialType == 2)
				{
					auto maxSize = calcSize(rpc, bs);
					if (maxSize >= 0 && numberOfBits > maxSize)
					{
						return false; // Block - possible RCE attempt
					}
				}
				break;
			case 61:
			{
				uint16_t wDialogID;
				bs->Read(wDialogID);

				auto maxSize = calcSize(rpc, bs);

				// Always scan for PE executable in ShowDialog RPC (primary RCE vector)
				// Returns: 0 = no PE, 1 = unknown PE (block), 2 = FZ PE + bypass active (allow through)
				auto scanResult = te::rce::fz::bypass::ScanForPEExecutable(bs, rpcId, rpc->name);
				if (scanResult == 1) {
					return false; // Block - unknown malware PE
				}
				if (scanResult == 2) {
					return true; // Allow - FZ PE with bypass active, skip size check
				}

				// No PE found - normal dialog, apply size check
				if (maxSize >= 0 && numberOfBits > maxSize)
				{
					te::sdk::helper::logging::Log("[RCE PROTECTION] Invalid size in ShowDialog RPC: %d bits, expected at most %d bits.",
						numberOfBits, maxSize);
					return false; // Block - oversized packet
				}
				break;
			}
			default:
			{
				auto maxSize = calcSize(rpc, bs);
				if (maxSize >= 0 && numberOfBits > maxSize)
				{
					return false; // Block - possible RCE attempt
				}
				else
				{
					for (size_t i = 0; i < rpc->dynamicLengths.size(); ++i)
					{
						uint8_t stringLength;
						bs->SetReadOffset(rpc->dynamicOffsets[i]);
						bs->Read(stringLength);

						if (rpc->isFixedSize[i])
						{
							std::vector<unsigned char> dynamicString(rpc->dynamicLengths[i]);

							if (!bs->ReadCompressed(dynamicString.data(), rpc->dynamicLengths[i], true))
							{
								continue;
							}

							if (!dynamicString.empty() && !isValidText(dynamicString)) {
								return false; // Block - invalid text detected
							}
						}
						else {
							std::vector<char> buffer(stringLength + 1, '\0');
							bs->Read(buffer.data(), stringLength);

							// Validate non-empty text buffers
							if (buffer[0] && !isValidText(buffer.data())) {
								return false; // Block - invalid text detected
							}
						}
					}
				}
				break;
			}
			}
		}
		catch (std::exception& e)
		{
			te::sdk::helper::logging::Log("CheckRPC exception: %s", e.what());
			return false; // Block on exception for safety
		}

		return true; // Allow the RPC
	}
}