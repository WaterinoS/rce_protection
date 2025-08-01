#include "te-rce-protection.h"
#include "te-fz-bypass.h"

#include <regex>

namespace te::rce::helper
{
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

	RPC* findRPCById(int rpcId) {
		for (auto& rpc : rpcListInBits) {  // Use a reference to avoid copying the elements
			if (rpc.id == rpcId) {
				return &rpc;
			}
		}
		return nullptr; // If RPC is not found
	}

	int calcSize(RPC* rpc, BitStream* bs) {
		RPC rpcCopyPtr = *rpc;

		int totalSize = rpcCopyPtr.baseSize;

		int currentOffset = rpcCopyPtr.dynamicLengths.size() > 0 ? rpcCopyPtr.dynamicOffsets[0] : 0;

		for (size_t i = 0; i < rpcCopyPtr.dynamicLengths.size(); ++i) {
			if (rpcCopyPtr.isFixedSize[i]) {
				totalSize += rpcCopyPtr.dynamicLengths[i];
			}
			else {
				bs->SetReadOffset(currentOffset);

				int dynamicLengthInBits = 0;

				if (rpcCopyPtr.dynamicLengths[i] == 8) {
					uint8_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}
				else if (rpcCopyPtr.dynamicLengths[i] == 16) {
					uint16_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}
				else if (rpcCopyPtr.dynamicLengths[i] == 32) {
					uint32_t dynamicLength = 0;
					bs->Read(dynamicLength);
					dynamicLengthInBits = dynamicLength;
				}

				dynamicLengthInBits = dynamicLengthInBits * 8;

				if (dynamicLengthInBits > INT_MAX / 8 || totalSize > INT_MAX - dynamicLengthInBits) {
					return -1;
				}

				totalSize += dynamicLengthInBits;

				if (i < rpcCopyPtr.dynamicOffsets.size() - 1) {
					currentOffset = rpcCopyPtr.dynamicOffsets[i + 1];
					currentOffset += dynamicLengthInBits;
				}
			}
		}

		return totalSize;
	}

	double calculateEntropy(const std::vector<unsigned char>& data) {
		if (data.size() > 1000000) { // Arbitrary limit to prevent abuse
			return 0.0;
		}

		std::array<int, 256> freq = { 0 };
		for (unsigned char c : data) {
			freq[c]++;
		}

		double entropy = 0.0;
		for (int f : freq) {
			if (f > 0) {
				double p = (double)f / data.size();
				entropy -= p * log2(p);
			}
		}
		return entropy;
	}

	double calculateEntropy(const std::string& data) {
		if (data.size() > 1000000) { // Arbitrary limit to prevent abuse
			return 0.0;
		}

		std::array<int, 256> freq = { 0 };

		for (unsigned char c : data) {  // std::string stores characters, but we can treat them as unsigned char
			freq[c]++;
		}

		double entropy = 0.0;
		for (int f : freq) {
			if (f > 0) {
				double p = static_cast<double>(f) / data.size();
				entropy -= p * log2(p);
			}
		}
		return entropy;
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

	std::vector<unsigned char> cleanText(const std::vector<unsigned char>& data) {
		std::string str(data.begin(), data.end());

		// Remove hex color codes in the format {XXXXXX}
		str = std::regex_replace(str, std::regex("\\{[0-9A-Fa-f]{6}\\}"), "");

		// Remove special characters like \r, \n, \t, etc.
		str = std::regex_replace(str, std::regex("[\\r\\n\\t]"), "");

		// Convert the cleaned string back to a vector of unsigned char
		return std::vector<unsigned char>(str.begin(), str.end());
	}

	bool isValidText(const std::vector<unsigned char>& data) {
		std::vector<unsigned char> cleanedData = cleanText(data);

		double entropy = calculateEntropy(cleanedData);
		return entropy <= 6.0 /*&& isValidUTF8(cleanedData)*/; // Threshold can be adjusted
	}

	std::string cleanText(const std::string& data) {
		// Remove hex color codes in the format {XXXXXX}
		std::string cleanedData = std::regex_replace(data, std::regex("\\{[0-9A-Fa-f]{6}\\}"), "");

		// Remove special characters like \r, \n, \t, etc.
		cleanedData = std::regex_replace(cleanedData, std::regex("[\\r\\n\\t]"), "");

		return cleanedData;
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

		for (size_t i = 0; i <= sizeOfImage - patternSize; ++i)
		{
			MEMORY_BASIC_INFORMATION mbi;
			if (!VirtualQuery(scanBytes + i, &mbi, sizeof(mbi)) ||
				mbi.State != MEM_COMMIT ||
				!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
			{
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
				if (maxSize >= 0 && numberOfBits > maxSize)
				{
					bool hasPE = te::rce::fz::bypass::ScanForPEExecutable(bs, rpcId, rpc ? rpc->name : "Unknown RPC");
					if (hasPE)
					{
						return false; // Block - malicious PE executable detected
					}
					return false; // Block - possible RCE attempt
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

							if (!buffer[0] && !isValidText(buffer.data())) {
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