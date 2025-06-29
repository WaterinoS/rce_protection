#include "te-sdk.h"

bool MyOutgoingPacketCallback(const te_sdk::PacketContext& ctx)
{
    printf("[TEST] OUTGOING PACKET: id=%i\n", ctx.packetId);
    return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // CONSOLE
        {
            AllocConsole();
            FILE* f;
            freopen_s(&f, "CONOUT$", "w", stdout);
            freopen_s(&f, "CONOUT$", "w", stderr);
            freopen_s(&f, "CONIN$", "r", stdin);
        }

        te_sdk::InitRakNetHooks();
		te_sdk::RegisterRaknetCallback(HookType::OutgoingPacket, MyOutgoingPacketCallback);
    }
    return TRUE;
}