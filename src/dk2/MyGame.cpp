//
// Created by DiaLight on 08.07.2024.
//
#include "dk2/MyGame.h"

#include <patches/logging.h>

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
    if (patch::control_windowed_mode::enabled) {
        isWindowed = true;  // todo: control
    }
    patch::log::dbg("start prepareScreen %dx%d bpp=%d w=%d ssw=%d hw=%d",
           dwWidth, dwHeight, dwRGBBitCount, isWindowed,
           screenSwap, screenHardware3D);
    int sel_dd_idx = this->selected_dd_idx;
    if (sel_dd_idx != this->last_selected_dd_idx) {
        MyResources_instance.video_settings.writeGuidIndex(sel_dd_idx);
        MyResources_instance.video_settings.writeGuidIndexIsDefault(0);
        MyResources_instance.video_settings.writeGuidIndexVerifiedWorking(0);
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
        if (!result) {
            patch::log::err("Screen Mode %d*%d (%d bpp) create window failed", dwWidth, dwHeight, dwRGBBitCount);
            return 0;
        }
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
        patch::log::err("Screen Mode %d*%d (%d bpp) is not available", dwWidth, dwHeight, dwRGBBitCount);
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
    int dwRGBBitCount_;
    if (isWindowed) {
        AABB aabb;
        int x = 50;
        int y = 50;
        patch::remember_window_location_and_size::patchWinLoc(x, y);
        aabb.minX = x;
        aabb.minY = y;
        aabb.maxX = dwWidth + x;
        aabb.maxY = dwHeight + y;
        int status;
        if (*this->c_window_test.probably_do_show_window_ev0_7((uint32_t *)&status, &aabb) < 0) {
            patch::log::err("Screen Mode %d*%d (%d bpp) show failed", dwWidth, dwHeight, dwRGBBitCount);
            return 0;
        }
        patch::remember_window_location_and_size::resizeWindow(this->c_window_test.hWnd);
        dwRGBBitCount_ = dwRGBBitCount;
    } else {
        dwRGBBitCount_ = dwRGBBitCount;
        int status;
        if (*dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount, initFlags, 0) < 0) {
            patch::log::err("Screen Mode %d*%d (%d bpp) dk2dd_init 1 failed", dwWidth, dwHeight, dwRGBBitCount);
            process_win_inputs();
            if (*dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount_, initFlags, 0) < 0) {
                patch::log::err("Screen Mode %d*%d (%d bpp) dk2dd_init 2 failed", dwWidth, dwHeight, dwRGBBitCount);
                return 0;
            }
        }
    }
    if (!cmd_flag_NOSOUND) {
        if (MySound_ptr->v_sub_567210())
            MySound_ptr->v_fun_5677E0();
        else
            MySound_ptr->v_set_number_of_channels(
                    MyResources_instance.soundCfg.numberOfChannels);
        MyResources_instance.soundCfg.readOrCreate();
    }
    this->isWindowed = isWindowed;
    this->dwWidth = dwWidth;
    this->dwHeight = dwHeight;
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
    updateMousePos.maxY = dwHeight;
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
    MyResources_instance.video_settings.writeGuidIndexIsDefault(0);
    MyResources_instance.video_settings.writeGuidIndexVerifiedWorking(1);
    HWND HWindow = getHWindow();
    ij_ImmAssociateContext(HWindow, 0);
    patch::log::dbg("prepareScreen %dx%d bpp=%d w=%d ssw=%d hw=%d success",
           dwWidth, dwHeight, dwRGBBitCount, isWindowed,
           screenSwap, screenHardware3D);
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
    bool winCreated = this->prepareScreenEx(
        MyResources_instance.video_settings.display_width,
        MyResources_instance.video_settings.display_height,
        MyResources_instance.video_settings.display_bitnes,
        MyResources_instance.video_settings.isWindowed,
        MyResources_instance.video_settings.screen_swap,
        MyResources_instance.video_settings.screen_hardware3D);
    if (!winCreated) {
        patch::log::dbg("failed to prepare screen. falling back to 640x480");
        winCreated = !this->prepareScreenEx(
            640,
            480,
            MyResources_instance.video_settings.display_bitnes,
            MyResources_instance.video_settings.isWindowed,
            MyResources_instance.video_settings.screen_swap,
            MyResources_instance.video_settings.screen_hardware3D);
        if (!winCreated) {
            patch::log::err("failed to prepare screen");
            return 0;
        }
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

namespace patch {

    void *try_unpack_jmp(void *fun) {
        if (fun == NULL) return NULL;
        uint8_t *p = (uint8_t*) fun;
        if (*p++ == 0xFF && *p++ == 0x25) { // follow jmp
            fun = **(void***) p;
        }
        return fun;
    }

}

void dk2::MyGame::removeWmActivateCallback(void *ptr) {;
    for (int i = 0; i < 8; ++i) {
        if (patch::try_unpack_jmp(this->WM_ACTIVATE_callbacks[i]) != patch::try_unpack_jmp(ptr)) continue;
        this->WM_ACTIVATE_callbacks[i] = NULL;
        this->WM_ACTIVATE_userData[i] = NULL;
        return;
    }
}
