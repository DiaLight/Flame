//
// Created by DiaLight on 20.01.2023.
//
#include <ddraw.h>
#include <map>
#include <gog_cfg.h>
#include <gog_fake.h>
#include <gog_patch.h>

using namespace gog;

bool gog::enable = true;

void _gog_print(const char *msg) {
    char msg_buf[1024];
    wsprintfA(msg_buf, "[GOG] %s\n", msg);
    OutputDebugStringA(msg_buf);
    printf("%s", msg_buf);
}

bool gog::patch_init() {
    gog::cfg::load();
    gog::fakeInit();
    if (gog::cfg::iSingleCore) {
        HANDLE hProc = GetCurrentProcess();
        SetProcessAffinityMask(hProc, 1);
    }
    if (gog::cfg::iDisableDEP) {
        HMODULE kernel32 = LoadLibraryA("kernel32.dll");
        typedef BOOL (WINAPI *SetProcessDEPPolicy_t)(_In_ DWORD dwFlags);
        auto SetProcessDEPPolicy = (SetProcessDEPPolicy_t) GetProcAddress(kernel32, "SetProcessDEPPolicy");
        if (SetProcessDEPPolicy) {
            SetProcessDEPPolicy(0);
        }
    }
    if (cfg::iCpuIdle) {
        timeBeginPeriod(1u);
    }
    return true;
}
