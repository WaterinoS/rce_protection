#include "te-sdk.h"

bool MyOutgoingPacketCallback(const te_sdk::PacketContext& ctx)
{
    printf("[TEST] OUTGOING PACKET: id=%i\n", ctx.packetId);
    return true;
}

void Init()
{
    while (!te_sdk::InitRakNetHooks())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    //te_sdk::RegisterRaknetCallback(HookType::OutgoingPacket, MyOutgoingPacketCallback);

    te_sdk::RegisterRaknetCallback(HookType::IncomingRpc, [](const te_sdk::PacketContext& ctx) {     
        // TODO RCE PROTECTION
        return true;
	});
	printf("[TEST] RakNet hooks initialized.\n");
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

        std::thread(Init).detach();
    }
    return TRUE;
}