//
// Created by DiaLight on 19.06.2024.
//
#include <algorithm>

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyMutex.h"
#include "patches/micro_patches.h"
#include "gog_patch.h"
#include "tools/bug_hunter.h"
#include "tools/command_line.h"
#include "patches/inspect_tools.h"
#include "patches/original_compatible.h"
#include "tools/console.h"
#include <thread>
#include <stdexcept>
#include <iostream>
#include <patches/game_version_patch.h>
#include <patches/screen_resolution.h>
#include <tools/flame_config.h>

#include "patches/protocol_dump.h"

namespace dk2 {

    bool dk2_main1(int argc, LPCSTR *argv);
    bool dk2_main2();

}

bool dk2::dk2_main2() {
    MyGame_instance.f28D = cmd_flag_NOERRORS;
    if ( MyResources_instance.video_settings.f9C )
        MyResources_instance.video_settings.sub_566DA0();
    if ( !cmd_flag_NOSOUND
         && !MySound_ptr->v_sub_567210()
         && !MySound_ptr->v_set_number_of_channels(
            MyResources_instance.soundCfg.numberOfChannels) ) {
        MySound_ptr->v_fun_567410();
        cmd_flag_NOSOUND = 1;
    }
    if ( cmd_flag_NOSOUND || CSpeechSystem_instance.sub_567F90() ) {
        if ( !WeaNetR_instance.init() ) {
            WeaNetR_instance.destroy();
            if ( !cmd_flag_NOSOUND ) {
                MySound_ptr->v_fun_567410();
                CSpeechSystem_instance.sub_568020();
            }
            if(patch::print_game_start_errors::enabled) {
                printf("failed to call WeaNetR_instance.init()\n");
            }
            return false;
        }
        if ( !MyGame_instance.isOsCompatible() ) {
            WeaNetR_instance.destroy();
            if ( !cmd_flag_NOSOUND ) MySound_ptr->v_fun_567410();
            if(patch::print_game_start_errors::enabled) {
                printf("failed to call MyGame_instance.isOsCompatible()\n");
            }
            return false;
        }
        if ( !all_components_fillStaticListeners() ) {
            WeaNetR_instance.destroy();
            if ( !cmd_flag_NOSOUND ) MySound_ptr->v_fun_567410();
            if(patch::print_game_start_errors::enabled) {
                printf("failed to call all_components_fillStaticListeners()\n");
            }
            return false;
        }
        if ( MyResources_instance.gameCfg.f124 ) {
            MyResources_instance.gameCfg.useFe_playMode = 1;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
        } else if ( MyResources_instance.gameCfg.f128 == 1 ) {
            MyResources_instance.gameCfg.useFe_playMode = 4;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
        } else if ( !cmd_flag_FrontEnd3D_unk8 ) {
            if ( MyGame_instance.getCpuSpeed() < 240.0 && getDevIdxSupportsLinearPerspective() != -1
                 || MyGame_instance.getCpuSpeed() < 290.0 && getDevIdxSupportsLinearPerspective() == -1 )
            {
                MyResources_instance.gameCfg.useFe2d_unk2 = 1;
            }
            MyResources_instance.gameCfg.useFe3d = 1;
            MyResources_instance.gameCfg.useFe_playMode = 5;
            _wcsncpy(MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 0x40u);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
            cmd_flag_FrontEnd3D_unk7 = 1;
        }
        // hook::ALL_READY_TO_START
        patch::screen_resolution::patchGameWindowResolution();
        CGameComponent *cur = &CGameComponent_instance;
        while (cur != nullptr) {
            if (!cur->v_handle()) break;
            CGameComponent *next = cur->v_mainGuiLoop();
            cur->v_f10_();
            cur = next;
        }
        all_components_clearStaticListeners();
        WeaNetR_instance.destroy();
        CSpeechSystem_instance.sub_568020();
        if ( !cmd_flag_NOSOUND )
            MySound_ptr->v_fun_567410();
    }
    return true;
}
bool dk2::dk2_main1(int argc, LPCSTR *argv) {
    CoInitialize(0);
    int status_2;
    setLibIconName(&status_2, 1000);
    struct _MEMORYSTATUS memoryStatus;
    memset(&memoryStatus, 0, sizeof(memoryStatus));
    cmd_flag_NOSOUND = 0;
    memoryStatus.dwLength = 32;
    GlobalMemoryStatus(&memoryStatus);
    if ( memoryStatus.dwAvailPhys + memoryStatus.dwAvailPageFile >= 0x12C00000 ) {
        if ( memoryStatus.dwAvailPhys + memoryStatus.dwAvailPageFile < 0x15E00000 )
            g_fontType = 1;
    } else {
        g_fontType = 2;
    }
    int status;
    struct _WIN32_FIND_DATAA FindFileData;
    findFile(&status, *argv, &FindFileData, -1);
    if (status >= 0) {
        g_fileChecksum = FindFileData.ftLastWriteTime.dwLowDateTime + FindFileData.ftLastWriteTime.dwHighDateTime;
        char *exeFilePath = (char *) argv[0];
        uint32_t hashsum_ = 0x5041554C;
        uint32_t hashsum = 0x5041554C;
        int status2;
        TbDiscFile *pTbDiscFile;
        if (*MyDiscFile_create(&status2, &pTbDiscFile, exeFilePath, 0x80000001) >= 0 ) {
            int sizeLeft_ = TbDiscFile_getSize(pTbDiscFile);
            int sizeLeft = sizeLeft_;
            if ( sizeLeft_ > 0 ) {
                char buf[8192];
                while (true) {
                    int blockSize = sizeLeft_;
                    if ( sizeLeft_ <= 0x2000 )
                        memset(buf, 0, sizeof(buf));
                    else
                        blockSize = 0x2000;
                    if ( (int)*TbDiscFile_readBytes(&status_2, pTbDiscFile, buf, blockSize, 0) < 0 ) {
                        hashsum_ = 0;
                        hashsum = 0;
                        sizeLeft = 0;
                    } else {
                        DWORD *pos = (DWORD *) buf;
                        sizeLeft -= blockSize;
                        int dwordsCount = (blockSize + 3) / 4;
                        if (dwordsCount > 0 ) {
                            do {
                                hashsum = _rotl(hashsum, 1);
                                hashsum_ = *pos++ ^ hashsum;
                                --dwordsCount;
                                hashsum = hashsum_;
                            } while(dwordsCount);
                        }
                    }
                    if (sizeLeft <= 0) break;
                    sizeLeft_ = sizeLeft;
                }
            }
            int status_;
            TbDiscFile_delete(&status_, pTbDiscFile);
        }
        g_fileHashsum = hashsum_;  // 1.7=FF542FAC
        patch::original_compatible::patch_hashsum();
        closeFindFile(&status_2, (int)&FindFileData);
    }
    MyResources_instance.readOrCreate();
    if (!parse_command_line(argc, argv)) {
        if(patch::print_game_start_errors::enabled) {
            printf("failed to parse command line\n");
        }
        return false;
    }
    if (!loadResources()) {
        if(patch::print_game_start_errors::enabled) {
            printf("failed to load resources\n");
        }
        return false;
    }

    patch::null_surf_fix::init();

    bool useDefaultWindowName = true;
    unsigned __int8 *MbString = MyMbStringList_idx1091_getMbString(42u);  // "Dungeon Keeper II"
    if ( MBToUni_convert(MbString, g_wchar_buf, 512) && unicodeToUtf8(g_wchar_buf, temp_string, 512) ) {
        int status_;
        setWindowName(&status_, temp_string);
        useDefaultWindowName = false;
    }
    if (useDefaultWindowName) {
        int status_;
        setWindowName(&status_, "Bullfrog Productions Ltd");
    }
    int DevIdxSupportsLinearPerspective = getDevIdxSupportsLinearPerspective();
    if ( (MyGame_instance.f50D & 0x800000) == 0 && DevIdxSupportsLinearPerspective == -1 ) {
        unsigned __int8 *mbString1 = MyMbStringList_idx1091_getMbString(2u);
        wchar_t wString1[512];
        if (MBToUni_convert(mbString1, wString1, 512)) {
            unsigned __int8 *mbString2 = MyMbStringList_idx1091_getMbString(0xB60u);
            wchar_t wString2[512];
            if (MBToUni_convert(mbString2, (wchar_t *)wString2, 512)) {
                WCHAR Text[512];
                dk2::_swprintf(Text, L"%s\n\n%s", wString1, wString2);
                HWND HWindow = getHWindow();
                MessageBoxW(HWindow, Text, g_wchar_buf, 0x10u);
                return false;
            }
        }
    }
    bool success = false;
    if(MyGame_instance.init()) {
        if(dk2_main2()) {
            success = true;
        } else {
            if(patch::print_game_start_errors::enabled) {
                printf("failed to call dk2_main2()\n");
            }
        }
    } else {
        if(patch::print_game_start_errors::enabled) {
            printf("failed to call MyGame_instance.init()\n");
        }
    }
    MyGame_instance.release();
    releaseResources();
    CoUninitialize();
    return success;
}

int __cdecl dk2::dk2_main(int argc, LPCSTR *argv) {
    uint32_t finalStatus = 0;
    MyMutex mutex;
    mutex.constructor("DKII MUTEX");
    if (!mutex.alredyExists ) {
        if(!dk2_main1(argc, argv)) {
            if(patch::print_game_start_errors::enabled) {
                MessageBoxA(NULL, "Game failed to start", "Flame", MB_OK);
            }
            finalStatus = -1;
            mutex.destroy();
            return 0;
        }
    } else if(patch::notify_another_instance_is_running::enabled) {
        printf("[ERROR]: another instance of DK2 is already running");
        MessageBoxA(NULL, "Another instance of DK2 is already running", "Dungeon Keeper 2", MB_OK);
    }

    finalStatus = -1;
    mutex.destroy();
    return 0;
}

int dk2::WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, CHAR *lpCmdLine, int nShowCmd) {
    setHInstance(hInstance);
    return dk2_main(g_argc, g_argv);
}

int __stdcall dk2::dk2_start() {
    DWORD Version = GetVersion();
    g_os_dwMinorVersion = Version >> 8;
    g_os_dwMajorVersion = Version;
    g_os_dwVersion = (Version >> 8) + (Version << 8);
    g_os_dwBuild = Version >> 16;
    if ( !__heap_init() )
        dk2::__amsg_exit_0(28);
    if ( !__mtinit() )
        dk2::__amsg_exit_0(16);
    // CPPEH_RECORD ms_exc;
    // ms_exc.registration.TryLevel = 0;
    dk2::__ioinit();
    dk2::___initmbctable();
    g_commandLineA = GetCommandLineA();
    g_environmentStrings = dk2::___crtGetEnvironmentStringsA();
    if ( !g_environmentStrings || !g_commandLineA )
        exit(-1);
    dk2::__setargv();
    dk2::__setenvp();
    dk2::__cinit();
    CHAR *lpCmdLine = g_commandLineA;
    if ( *g_commandLineA == '"' ) {
        while ( *++lpCmdLine != '"' && *lpCmdLine ) {
            if ( dk2::__ismbblead(*lpCmdLine) ) ++lpCmdLine;
        }
        if ( *lpCmdLine == '"' ) ++lpCmdLine;
    } else {
        while ( *lpCmdLine > 0x20u ) ++lpCmdLine;
    }
    while ( *lpCmdLine && *lpCmdLine <= 0x20u ) ++lpCmdLine;
    struct _STARTUPINFOA StartupInfo;
    StartupInfo.dwFlags = 0;
    GetStartupInfoA(&StartupInfo);
    int wShowWindow;
    if ( (StartupInfo.dwFlags & 1) != 0 )
        wShowWindow = StartupInfo.wShowWindow;
    else
        wShowWindow = 10;
    int nShowCmd = wShowWindow;
    HMODULE ModuleHandleA = GetModuleHandleA(NULL);
    int result = dk2::WinMain(ModuleHandleA, NULL, lpCmdLine, nShowCmd);
    {  // flame patch
        dk2::_doexit(result, 0, 1);
        return result;
    }
    exit(result);
}


flame_config::define_flame_option<bool> o_console(
    "flame:console",
    "Show console window to see logs\n",
    false
);
flame_config::define_flame_option<bool> o_windowed(
    "flame:windowed",
    "Open game in windowed mode\n",
    false
);
flame_config::define_flame_option<bool> o_no_initial_size(
    "flame:no-initial-size",
    "Disable autoresize window\n"
    "Used only in windowed mode\n",
    false
);

int main(int argc, const char **argv) {
    command_line_init(argc, argv);
    bug_hunter::init();

    if (cmdl::hasFlag("h") || cmdl::hasFlag("help") || cmdl::hasFlag("-help")) {
#if !DEV_FORCE_CONSOLE
        initConsole();
#endif
        flame_config::help();
#if !DEV_FORCE_CONSOLE
        std::cout << '\n' << "Press a key to continue...";
        std::cin.get();
#endif
        return 0;
    }
    if (cmdl::hasFlag("v") || cmdl::hasFlag("version") || cmdl::hasFlag("-version")) {
#if !DEV_FORCE_CONSOLE
        initConsole();
#endif
        std::string version = patch::game_version_patch::getFileVersion();
        std::replace(version.begin(), version.end(), '\n', ' ');
        std::cout << "DKII" << version << std::endl;
#if !DEV_FORCE_CONSOLE
        std::cout << '\n' << "Press a key to continue...";
        std::cin.get();
#endif
        return 0;
    }

    if (!CreateDirectory("flame", NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
#if !DEV_FORCE_CONSOLE
        initConsole();
#endif
        std::cerr << "unable to create flame directory" << std::endl;
#if !DEV_FORCE_CONSOLE
        std::cout << '\n' << "Press a key to continue...";
        std::cin.get();
#endif
        return -1;
    }
    {
        std::string config = "flame/config.toml";
        auto it = cmdl::dict.find("c");
        if (it == cmdl::dict.end()) it = cmdl::dict.find("-config");
        if (it != cmdl::dict.end()) {
            if (!it->second.empty()) config = it->second;
        }
        flame_config::load(config);
    }

    flame_config::save();
#if !DEV_FORCE_CONSOLE
    // in windowed mode we can attach console with flag
    if(o_console.get()) {
        initConsole();
    }
#endif

    if(o_windowed.get()) {
        gog::enable = false;  // gog is incompatible with windowed mode
        patch::control_windowed_mode::enabled = true;
        if(!o_no_initial_size.get()) {
            // Finding the user's screen resolution
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            int height;
            int width;
            if(screenHeight < screenWidth) {
                height = screenHeight * 5 / 6;
                width = height * 12 / 9;
            } else {
                width = screenWidth * 5 / 6;
                height = width * 9 / 12;
            }
            patch::remember_window_location_and_size::setInitialSize(width, height);
        }
    }

    patch::override_max_room_count::init();
    patch::inspect_tools::init();
    patch::multi_interface_fix::init();
    patch::original_compatible::init();
    patch::protocol_dump::init();
    patch::screen_resolution::init();

    HANDLE hThread = CreateThread(NULL, 0, [](void *) -> DWORD {
        bug_hunter::keyWatcher();
        return 0;
    }, NULL, 0, NULL);
    // call entry point of DKII.EXE,
    if(gog::enable) gog::patch_init();
    // initialize its runtime and call dk2::WinMain
    int result = dk2::dk2_start();
    bug_hunter::stopped = true;
    if (WaitForSingleObject(hThread, 500) == WAIT_TIMEOUT) TerminateThread(hThread, 0);
    if (flame_config::changed()) flame_config::save();
    return result;
}


