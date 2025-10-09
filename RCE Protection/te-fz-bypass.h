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

	bool ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName);
	bool InstallAntiDetectionHooks();
}