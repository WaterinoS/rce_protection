#include "te-rce-protection.h"
#include "FullRaknet/PacketEnumerations.h"

bool OnIncomingRPC(const te_sdk::RpcContext& ctx)
{
    return te::rce::helper::CheckRPC(ctx.rpcId, (BitStream*)ctx.bitStream);
}

bool OnIncomingPacket(const te_sdk::PacketContext& ctx)
{
    if (ctx.packetId == PacketEnumeration::ID_MARKERS_SYNC)
    {
        int				iNumberOfPlayers = 0;
        uint16_t		playerID = uint16_t(-1);
        short			sPos[3] = { 0, 0, 0 };
        bool			bIsPlayerActive = false;

        (*(BitStream*)ctx.bitStream).IgnoreBits(8);
        (*(BitStream*)ctx.bitStream).Read(iNumberOfPlayers);
        if (iNumberOfPlayers < 0 || iNumberOfPlayers >  1004/*SAMP_MAX_PLAYERS*/)
            return false;

        auto remainingSize = (*(BitStream*)ctx.bitStream).GetNumberOfUnreadBits() / 8;
        if (remainingSize > (sizeof(uint16_t) + sizeof(bool) + 3 * sizeof(int16_t)) * iNumberOfPlayers)
        {
            te_sdk::helper::logging::Log("[RCE PROTECTION] Invalid size in MarkersSync packet: %d bytes, expected at most %d bytes for %d players.",
                remainingSize, (sizeof(uint16_t) + sizeof(bool) + 3 * sizeof(int16_t)) * iNumberOfPlayers, iNumberOfPlayers);
            return false;
        }
	}

    return true;
}

void Init()
{
    while (!te_sdk::InitRakNetHooks())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    te_sdk::RegisterRaknetCallback(HookType::IncomingRpc, OnIncomingRPC);
    te_sdk::RegisterRaknetCallback(HookType::IncomingPacket, OnIncomingPacket);

	//printf("[TEST] RakNet hooks initialized.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // CONSOLE
        {
            /*
                AllocConsole();
                FILE* f;
                freopen_s(&f, "CONOUT$", "w", stdout);
                freopen_s(&f, "CONOUT$", "w", stderr);
                freopen_s(&f, "CONIN$", "r", stdin);
            */
        }

        std::thread(Init).detach();
    }
    return TRUE;
}