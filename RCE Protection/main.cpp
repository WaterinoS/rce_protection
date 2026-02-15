#include <utility>
#include <WinSock2.h>
#include <WS2tcpip.h>

#include "te-rce-protection.h"
#include "te-fz-bypass.h"
#include "FullRaknet/PacketEnumerations.h"

#include <d3d9.h>
#include <MinHook.h>

#pragma comment(lib, "ws2_32.lib")

using namespace RakNet;

bool OnIncomingRPC(const te::sdk::RpcContext& ctx)
{
    return te::rce::helper::CheckRPC(ctx.rpcId, static_cast<BitStream*>(ctx.bitStream));
}

bool OnIncomingPacket(const te::sdk::PacketContext& ctx)
{
    if (ctx.packetId == PacketEnumeration::ID_MARKERS_SYNC)
    {
        uint32_t		iNumberOfPlayers = 0;

        (*static_cast<BitStream*>(ctx.bitStream)).IgnoreBits(8);
        (*static_cast<BitStream*>(ctx.bitStream)).Read(iNumberOfPlayers);
        if (iNumberOfPlayers > 1004/*SAMP_MAX_PLAYERS*/)
            return false;

        auto remainingBitsSize = (*static_cast<BitStream*>(ctx.bitStream)).GetNumberOfUnreadBits();
        auto expectedMaxBitsSize = (1 + 16 + (3 * 16)) * iNumberOfPlayers;
        if (std::cmp_greater(remainingBitsSize, expectedMaxBitsSize))
        {
			te::sdk::helper::logging::Log("[RCE PROTECTION] Invalid size in MarkersSync packet: %d bits, expected at most %d bits for %d players.",
				remainingBitsSize, expectedMaxBitsSize, iNumberOfPlayers);
            return false;
        }
	}

    return true;
}

bool OnOutgoingRPC(const te::sdk::RpcContext& ctx)
{
    if (ctx.rpcId == 25/*ClientJoin*/)
    {
        te::sdk::helper::samp::AddChatMessage("[#TE] Universal RCE Protection by WaterSmoke Loaded !", D3DCOLOR_XRGB(128, 235, 52));
		te::sdk::helper::samp::AddChatMessage("[#TE] FenixZone Anticheat bypass included.", D3DCOLOR_XRGB(255, 165, 0));
	}
    return true;
}

void Init()
{
	te::sdk::helper::logging::SetModName("RCE Protection");

    while (!te::sdk::InitRakNetHooks())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    te::sdk::RegisterRaknetCallback(HookType::IncomingRpc, OnIncomingRPC);
    te::sdk::RegisterRaknetCallback(HookType::IncomingPacket, OnIncomingPacket);
    te::sdk::RegisterRaknetCallback(HookType::OutgoingRpc, OnOutgoingRPC);
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
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // Disable all MinHook hooks and uninitialize
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
    }
    return TRUE;
}
