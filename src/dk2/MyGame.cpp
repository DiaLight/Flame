//
// Created by DiaLight on 08.07.2024.
//
#include "dk2/MyGame.h"
#include "dk2/utils/Pos2i.h"
#include "dk2/utils/AABB.h"
#include "dk2/DxDeviceInfo.h"
#include "dk2/DxModeInfo.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"

int dk2::MyGame::prepareScreenEx(
        uint32_t dwWidth,
        uint32_t dwHeight,
        uint32_t dwRGBBitCount,
        int isWindowed,
        int screenSwap,
        int screenHardware3D) {
    if (control_windowed_mode::enabled) {
//        printf("prepareScreen %p %dx%d %d %d %d %d\n",
//               this, dwWidth, dwHeight, dwRGBBitCount, isWindowed,
//               screenSwap, screenHardware3D);
        isWindowed = true;  // todo: control
    }
    int sel_dd_idx = this->selected_dd_idx;
    if (sel_dd_idx != this->last_selected_dd_idx) {
        MyResources_instance.video_settings.sub_566E40(sel_dd_idx);
        MyResources_instance.video_settings.sub_566F40(0);
        MyResources_instance.video_settings.sub_566EC0(0);
        if (isGameWindowCreated == 1) {
            setDebugStringFun(debugMsgBox);
            this->zbufferSurf = 0;
            this->c_window_test.recreate();
            IDirect3D2 *f6D_pIDirect3D2 = this->pIDirect3D2;
            if (f6D_pIDirect3D2) {
                f6D_pIDirect3D2->Release();
                this->pIDirect3D2 = 0;
            }
            uint32_t status;
            dk2wnd_cleanup(&status);
            BullfrogWindow_destroy();
            isGameWindowCreated = 0;
        }
        int result = this->createWindow(0);
        if (!result)
            return result;
    }
    int last_selected_dd_idx = this->last_selected_dd_idx;
    int ddraw_idx;
    DxDeviceInfo *v13;
    int f1FE_modeListCount;
    if (last_selected_dd_idx >= ddraw_device_count
        || (ddraw_idx = 0,
            v13 = &ddraw_devices[last_selected_dd_idx],
            f1FE_modeListCount = v13->modeListCount,
            f1FE_modeListCount <= 0)) {
        LABEL_14:
        MyGame_debugMsg(this, "Screen Mode %d*%d (%d bpp) is not available\n", dwWidth, dwHeight, dwRGBBitCount);
        return 0;
    }
    DxModeInfo *f206_modeList = v13->modeList;
    while (f206_modeList->dwWidth != dwWidth
           || f206_modeList->dwHeight != dwHeight
           || f206_modeList->dwRGBBitCount != dwRGBBitCount) {
        ++ddraw_idx;
        ++f206_modeList;
        if (ddraw_idx >= f1FE_modeListCount)
            goto LABEL_14;
    }
    void (__cdecl **fE89_WM_ACTIVATE_callbacks)(int, uint32_t, uint32_t, void *);
    fE89_WM_ACTIVATE_callbacks = this->WM_ACTIVATE_callbacks;
    int left = 8;
    void (__cdecl **callbacks)(int, uint32_t, uint32_t, void *);
    callbacks = this->WM_ACTIVATE_callbacks;
    do {
        if (*fE89_WM_ACTIVATE_callbacks)
            (*fE89_WM_ACTIVATE_callbacks)(2, 0, 0, fE89_WM_ACTIVATE_callbacks[8]);
        ++fE89_WM_ACTIVATE_callbacks;
        --left;
    } while (left);
    setDebugStringFun(debugMsgBox);
    int screenHardware3D_ = screenHardware3D;
    bool isFullscreen = isWindowed == 0;
    int screenSwap_ = screenSwap;
    this->zbufferSurf = 0;
    int initFlags;
    if (isFullscreen) {
        if (screenSwap_) {
            initFlags = 1;
            if (screenHardware3D_)
                initFlags = 0x49;
        } else {
            initFlags = 2;
            if (screenHardware3D_)
                initFlags = 0x4A;
        }
    } else if (screenSwap_) {
        initFlags = 0x11;
    } else {
        initFlags = 0x10;
        if (screenHardware3D_)
            initFlags = 0x58;
    }
    if (!cmd_flag_NOSOUND && MySound_ptr->v_sub_567210())
        MySound_ptr->v_fun_5677D0();
    this->c_window_test.recreate();
    int dwHeight_;
    int dwRGBBitCount_;
    if (isWindowed) {
        dwHeight_ = dwHeight;
        AABB aabb;
        int x = 50;
        int y = 50;
        remember_window_location_and_size::patchWinLoc(x, y);
        aabb.minX = x;
        aabb.minY = y;
        aabb.maxX = dwWidth + x;
        aabb.maxY = dwHeight + y;
        if (*this->c_window_test.probably_do_show_window_ev0_7(&dwHeight, &aabb) < 0)
            return 0;
        remember_window_location_and_size::resizeWindow(this->c_window_test.hWnd);
        dwRGBBitCount_ = dwRGBBitCount;
    } else {
        dwRGBBitCount_ = dwRGBBitCount;
        int status;
        if (*dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount, initFlags, 0) < 0) {
            process_win_inputs();
            if (*dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount_, initFlags, 0) < 0)
                return 0;
        }
        dwHeight_ = dwHeight;
    }
    if (!cmd_flag_NOSOUND) {
        if (MySound_ptr->v_sub_567210())
            MySound_ptr->v_fun_5677E0();
        else
            MySound_ptr->v_set_number_of_channels(
                    MyResources_instance.soundCfg.numberOfChannels);
        MyResources_instance.soundCfg.resolveValues();
    }
    this->isWindowed = isWindowed;
    this->dwWidth = dwWidth;
    this->dwHeight = dwHeight_;
    this->dwRGBBitCount = dwRGBBitCount_;
    this->_prepareScreen_a6 = screenSwap;
    this->_prepareScreen_a7 = screenHardware3D_;
    this->f18 = 0;
    this->collect3dDevices();
    this->f4C_.fun_559820(0);
    setDebugStringFun(MyGame_static_559050_parse);
    if (MyResources_instance.video_settings.zbuffer_bitnes == 16) {
        if (!this->createZBufferSurf(0x10u) && !this->createZBufferSurf(0x20u))
            this->createZBufferSurf(0x18u);
    } else if (MyResources_instance.video_settings.zbuffer_bitnes == 32
               && !this->createZBufferSurf(0x20u)
               && !this->createZBufferSurf(0x18u)) {
        this->createZBufferSurf(0x10u);
    }
    // move mouse to center
    int mousePos_y = (unsigned int) this->dwHeight >> 1;
    Pos2i mousePos;
    mousePos.x = (unsigned int) this->dwWidth >> 1;
    mousePos.y = mousePos_y;
    MyInputManagerCb_static_setMousePos(&mousePos);
    // direct invoke mouse updater
    AABB updateMousePos;
    updateMousePos.minX = 0;
    updateMousePos.minY = 0;
    updateMousePos.maxX = dwWidth;
    updateMousePos.maxY = dwHeight_;
    MyInputManagerCb_static_updateMouse(&updateMousePos);
    void (__cdecl **callbacks_)(int, uint32_t, uint32_t, void *); // esi
    callbacks_ = callbacks;
    int left2 = 8;
    do {
        if (*callbacks_)
            (*callbacks_)(3, 0, 0, callbacks_[8]);
        ++callbacks_;
        --left2;
    } while (left2);
    MyResources_instance.video_settings.sub_566F40(0);
    MyResources_instance.video_settings.sub_566EC0(1);
    HWND HWindow = getHWindow();
    ij_ImmAssociateContext(HWindow, 0);
    return 1;
}

namespace dk2 {
    void inline_selectDrawEngine(dk2::MyGame *game);
}
int dk2::MyGame::init() {
    inline_selectDrawEngine(this);
    int status;
    if (*MyInputManagerCb_static_initKeyInputs(&status) < 0) {
        return 0;
    }
    int status_;
    if (*MyInputManagerCb_static_initCursorInputs(&status_) < 0) {
        return 0;
    }
    if (!this->createWindow(1)) {
        return 0;
    }
    if (!this->prepareScreenEx(
            MyResources_instance.video_settings.display_width,
            MyResources_instance.video_settings.display_height,
            MyResources_instance.video_settings.display_bitnes,
            MyResources_instance.video_settings.isWindowed,
            MyResources_instance.video_settings.screen_swap,
            MyResources_instance.video_settings.screen_hardware3D)
        && !this->prepareScreenEx(
            640,
            480,
            MyResources_instance.video_settings.display_bitnes,
            MyResources_instance.video_settings.isWindowed,
            MyResources_instance.video_settings.screen_swap,
            MyResources_instance.video_settings.screen_hardware3D)) {
        printf("failed to prepare screen\n");
        return 0;
    }
    setCustomDefWindowProcA((int) myCustomDefWindowProcA);
    WinEventHandlers_instance.addHandler(
            0,
            (void (__stdcall *)(int, int, void *)) static_MyGame_Event07_cb,
            this);
    this->fE71 = 0;
    this->fE75 = 0;
    this->recreateRequest = 0;
    this->fE7D = 0;
    this->moonAge = calc_moon_age();
    this->f0 = 1;
    this->fF51 = 0;
    return 1;
}
