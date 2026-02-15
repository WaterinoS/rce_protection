#pragma once
#include "te-sdk.h"

using namespace RakNet;

namespace te::rce::fz::bypass
{
	struct PatternData {
		std::vector<uint8_t> bytes;
		std::vector<uint8_t> mask;  // 1 = must match, 0 = wildcard
		uint8_t              firstByte;
		bool                 firstWildcard;
	};

	// Returns: 0 = no PE found, 1 = unknown PE blocked, 2 = FZ PE (allow through, delayed scanner active)
	int ScanForPEExecutable(BitStream* bs, int rpcId, const std::string& rpcName);
	bool InstallAntiDetectionHooks();
}