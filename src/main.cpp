//
// Created by DiaLight on 19.06.2024.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyMutex.h"
#include "patches/micro_patches.h"

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
            MyResources_instance.obj_29CB.numberOfChannels) ) {
        MySound_ptr->v_fun_567410();
        cmd_flag_NOSOUND = 1;
    }
    if ( cmd_flag_NOSOUND || CSpeechSystem_instance.sub_567F90() ) {
        if ( !WeaNetR_instance.init() ) {
            WeaNetR_instance.sub_559CB0();
            if ( !cmd_flag_NOSOUND ) {
                MySound_ptr->v_fun_567410();
                CSpeechSystem_instance.sub_568020();
            }
            return false;
        }
        if ( !MyGame_instance.isOsCompatible() ) {
            WeaNetR_instance.sub_559CB0();
            if ( !cmd_flag_NOSOUND ) MySound_ptr->v_fun_567410();
            return false;
        }
        if ( !all_components_fillStaticListeners() ) {
            WeaNetR_instance.sub_559CB0();
            if ( !cmd_flag_NOSOUND ) MySound_ptr->v_fun_567410();
            return false;
        }
        if ( MyResources_instance.f2B2B ) {
            MyResources_instance.useFe = 1;
            MyResources_instance.f2A13 = 3;
        } else if ( MyResources_instance.f2B2F == 1 ) {
            MyResources_instance.useFe = 4;
            MyResources_instance.f2A13 = 3;
        } else if ( !cmd_flag_FrontEnd3D_unk8 ) {
            if ( MyGame_instance.sub_559790() < 240.0 && getDevIdxSupportsLinearPerspective() != -1
                 || MyGame_instance.sub_559790() < 290.0 && getDevIdxSupportsLinearPerspective() == -1 )
            {
                MyResources_instance.f2B77 = 1;
            }
            MyResources_instance.useFe3d = 1;
            MyResources_instance.useFe = 5;
            wcsncpy(MyResources_instance.f2A17, L"FrontEnd3DLevel", 0x40u);
            MyResources_instance.f2A17[63] = 0;
            MyResources_instance.f2B1B = 0;
            MyResources_instance.f2A13 = 3;
            cmd_flag_FrontEnd3D_unk7 = 1;
        }
        CGameComponent *cur = &CGameComponent_instance;
        while (cur != nullptr) {
            if (!cur->v_handle()) break;
            CGameComponent *next = cur->v_mainGuiLoop();
            cur->v_f10_();
            cur = next;
        }
        all_components_clearStaticListeners();
        WeaNetR_instance.sub_559CB0();
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
        g_fileHashsum = hashsum_;
        closeFindFile(&status_2, (int)&FindFileData);
    }
    MyResources_instance.sub_55B120();
    if ( !parse_command_line(argc, argv) || !loadResources() ) return false;
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
    bool success = MyGame_instance.init() && dk2_main2();
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
            finalStatus = -1;
            mutex.destroy();
            return 0;
        }
    } else if(notify_another_instance_is_running::enabled) {
        printf("[ERROR]: another instance of DK2 is running");
    }

    finalStatus = -1;
    mutex.destroy();
    return 0;
}

int dk2::WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, CHAR *lpCmdLine, int nShowCmd) {
    setHInstance(hInstance);
    return dk2_main(g_argc, g_argv);
}

int main() {
    // call entry point of DKII.EXE,
    // initialize its runtime and call dk2::WinMain
    dk2::dk2_start();
}
