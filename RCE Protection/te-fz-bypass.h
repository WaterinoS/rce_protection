#pragma once
#include "te-sdk.h"

namespace te::rce::fz::bypass
{
	struct PatternData {
		std::vector<uint8_t> bytes;
		std::vector<bool>    mask;
		uint8_t              firstByte;
		bool                 firstWildcard;
	};

	extern std::unordered_map<std::string, PatternData> s_patternCache;
	using tTerminateGTA = void(__stdcall*)(HWND, UINT, UINT_PTR, DWORD);

	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName);
}