#pragma once
#include "te-sdk.h"

namespace te::rce::helper
{
	struct RPC {
		int id;
		std::string name;
		int baseSize;
		std::vector<int> dynamicLengths;
		std::vector<int> dynamicOffsets;
		std::vector<bool> isFixedSize;
	};

	uint32_t PatternScan(uint32_t pModuleBaseAddress, const char* sSignature, bool bSkipFirst);
	bool CheckRPC(int rpcId, BitStream* bs);
}