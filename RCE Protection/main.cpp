#include "te-rce-protection.h"

bool OnIncomingRPC(const te_sdk::RpcContext& ctx)
{
	te_sdk::helper::logging::Log("[RCE PROTECTION] Incoming RPC: %i", ctx.rpcId);

    auto validation_result = te::rce::helper::CheckRPC(ctx.rpcId, (BitStream*)ctx.bitStream);
    if (!validation_result.empty())
    {
        for (const auto& message : validation_result)
        {
            te_sdk::helper::logging::Log("[RCE PROTECTION] %s", message.c_str());
        }
        return false; // Block the RPC
    }
    return true; // Allow the RPC
}

void Init()
{
    while (!te_sdk::InitRakNetHooks())
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
	}

    te_sdk::RegisterRaknetCallback(HookType::IncomingRpc, OnIncomingRPC);

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