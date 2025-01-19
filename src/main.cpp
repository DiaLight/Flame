//
// Created by DiaLight on 19.06.2024.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyMutex.h"
#include "patches/micro_patches.h"
#include "gog_patch.h"
#include "tools/bug_hunter.h"
#include "weanetr_dll/weanetr.h"
#include "tools/command_line.h"
#include "patches/inspect_tools.h"
#include "patches/original_compatible.h"
#include <thread>
#include <stdexcept>
#include <iostream>

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
            if ( MyGame_instance.sub_559790() < 240.0 && getDevIdxSupportsLinearPerspective() != -1
                 || MyGame_instance.sub_559790() < 290.0 && getDevIdxSupportsLinearPerspective() == -1 )
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
    MyResources_instance.sub_55B120();
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


int main(int argc, const char **argv) {
    const char *roomsLimitStr = getCmdOption(argv, argv + argc, "-experimental_rooms_limit");
    if (roomsLimitStr != nullptr) {
        try {
            uint32_t roomsLimit = std::stoul(roomsLimitStr, nullptr, 10);
            patch::override_max_room_count::limit = roomsLimit;
        } catch(std::invalid_argument &e) {
            std::cout << "cant parse int \"" << roomsLimitStr << "\"" << std::endl;
            exit(-1);
        }
    }
    if(!hasCmdOption(argv, argv + argc, "-console")) {
        ::ShowWindow(::GetConsoleWindow(), SW_HIDE);
    }
    if(hasCmdOption(argv, argv + argc, "-windowed")) {
        gog::enable = false;  // gog is incompatible with windowed mode
        patch::control_windowed_mode::enabled = true;
        if(!hasCmdOption(argv, argv + argc, "-no_initial_size")) {
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

    patch::inspect_tools::init();
    bug_hunter::init();
    net::init();

    std::thread keyWatcher([] { bug_hunter::keyWatcher(); });
    // call entry point of DKII.EXE,
    if(gog::enable) gog::patch_init();
    // initialize its runtime and call dk2::WinMain
    dk2::dk2_start();
}


