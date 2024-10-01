//
// Created by DiaLight on 16.08.2024.
//
#include <Windows.h>
#include <cstdio>
#include "mimicry.h"
#include "mimicry.h"
#include "console.h"
#include "game_version.h"
#include "write_protect.h"
#include "dev_mouse_dinput_to_user32.h"
#include <cstdint>
#include <exception>
#include <vector>

#define dk2_virtual_base 0x00400000

uintptr_t dk2_base = 0;

uintptr_t addr(uint32_t va) {
    return (dk2_base + (va - dk2_virtual_base));
}

typedef int (*loadResources_t)();
loadResources_t orig_loadResources = nullptr;
int proxy_loadResources() {
    // make 32 bit everything
    auto ptr = (uint32_t *) addr(dk2_version == 170 ? 0x00759A98 : 0x007546A4);
    {
        write_protect prot(ptr, sizeof(void *));
        *ptr = 1;
    }
    ptr = (uint32_t *) addr(dk2_version == 170 ? 0x00759A88 : 0x00754694);
    {
        write_protect prot(ptr, sizeof(void *));
        *ptr = 32;
    }
    ptr = (uint32_t *) addr(dk2_version == 170 ? 0x00759A84 : 0x00754690);
    {
        write_protect prot(ptr, sizeof(void *));
        *ptr = 32;
    }
    return orig_loadResources();
}

typedef int (__fastcall *MyGame_prepareScreenEx_t)(
        void *this_, void *edx, int dwWidth, int dwHeight, int dwRGBBitCount,
        int isWindowed, int screenSwap, int screenHardware3D);
MyGame_prepareScreenEx_t orig_MyGame_prepareScreenEx = nullptr;
int __fastcall proxy_MyGame_prepareScreenEx(
        void *this_, void *edx, int dwWidth, int dwHeight, int dwRGBBitCount,
        int isWindowed, int screenSwap, int screenHardware3D) {
    printf("prepareScreen %p %dx%d %d %d %d %d\n",
            this_, dwWidth, dwHeight, dwRGBBitCount, isWindowed, screenSwap, screenHardware3D);
    int ret = orig_MyGame_prepareScreenEx(
            this_, edx, dwWidth, dwHeight, dwRGBBitCount, true, screenSwap,screenHardware3D);
    return ret;
}

LONG WINAPI unhandledFilter(_In_ struct _EXCEPTION_POINTERS *ExceptionInfo) {
//    MessageBoxA(NULL, "Exception", "Exception", MB_OK);
    return EXCEPTION_CONTINUE_SEARCH;
}
bool devhelper_initialize(void *devHelperBase) {
    SetUnhandledExceptionFilter(unhandledFilter);
    // make os compatible
    if(dk2_version == 170) {
        auto pGetVersion = (uint8_t *) addr(0x00557FB5);
        {
            write_protect prot(pGetVersion, sizeof(void *));
            *pGetVersion = 11;
        }
    } else if(dk2_version == 151) {
        auto pSbbEaxEax = (uint8_t *) addr(0x005546CF);
        {
            write_protect prot(pSbbEaxEax, sizeof(void *));
            *pSbbEaxEax = 0x33;  // xor eax, eax
        }
    }
    // fix for pure 151 but bad for GIM
//    if(dk2_version == 151) {
//        auto pSbbEaxEax = (uint8_t *) addr(0x0063BE74 + 2);
//        {
//            write_protect prot(pSbbEaxEax, sizeof(void *));
//            *pSbbEaxEax = 0xFC;
//        }
//    }
    // make 32 bit everything
    orig_loadResources = (loadResources_t) addr(dk2_version == 170 ? 0x00552F10 : 0x0054F7F0);
    uintptr_t xref = dk2_version == 170 ? 0x005A5FBC : 0x005A0DFE;
    auto pos = addr(xref + 1);
    {
        write_protect prot((void *) pos, sizeof(uintptr_t));
        *(DWORD *) pos = (uintptr_t) proxy_loadResources - (pos + 4);
    }
    // reduce title screen time
    pos = addr(dk2_version == 170 ? 0x005341E1 : 0x00530EB1);
    {
        write_protect prot((void *) pos, sizeof(uint32_t));
        *(uint32_t *) pos = 100;  // sleep time
    }

    orig_MyGame_prepareScreenEx = (MyGame_prepareScreenEx_t) addr(dk2_version == 170 ? 0x005581B0 : 0x005547B0);
    std::vector<uintptr_t> xrefs_170 = {0x00401C20, 0x00401C98, 0x00401D10, 0x00401D66, 0x00401DBC, 0x00401E12, 0x00401E68, 0x00401EBE, 0x00401F14, 0x00401F6A, 0x00401FC0, 0x00402016, 0x00525DC7, 0x00525E6E, 0x0052F22A, 0x00557E2F, 0x00557E5F, 0x00558836, 0x00558C0D, 0x00558C57};
    std::vector<uintptr_t> xrefs_151 = {0x00401BC0, 0x00401C38, 0x00401CB0, 0x00401D06, 0x00401D5C, 0x00401DB2, 0x00401E08, 0x00401E5E, 0x00401EB4, 0x00401F0A, 0x0052227D, 0x00522324, 0x0052BB75, 0x00554549, 0x00554579, 0x00554E26, 0x005551CD, 0x00555217};

    for (const auto &xref : (dk2_version == 170 ? xrefs_170 : xrefs_151)) {
        auto pos = addr(xref + 1);
        write_protect prot((void *) pos, sizeof(uintptr_t));
        *(DWORD *) pos = (uintptr_t) proxy_MyGame_prepareScreenEx - (pos + 4);
    }

    dev_mouse_dinput_to_user32::initialize();

    return true;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            if(!initMimicry()) {
                MessageBoxA(NULL, "init mimicry failed", "DevHelper error", MB_OK);
                return FALSE;
            }
            if(!initConsole()) {
                MessageBoxA(NULL, "init console failed", "DevHelper error", MB_OK);
                return FALSE;
            }
            if(!initGameVersion()) {
                MessageBoxA(NULL, "init version failed", "DevHelper error", MB_OK);
                return FALSE;
            }
            dk2_base = (uintptr_t) GetModuleHandleA(NULL);
            if(!devhelper_initialize(hinstDLL)) {
                MessageBoxA(NULL, "init environment failed", "DevHelper error", MB_OK);
                return FALSE;
            }
            break;
        case DLL_THREAD_ATTACH:
            // Do thread-specific initialization.
            break;
        case DLL_THREAD_DETACH:
            // Do thread-specific cleanup.
            break;
        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr) {
                break; // do not do cleanup if process termination scenario
            }
            // Perform any necessary cleanup.
            break;
    }
    return TRUE;
}
