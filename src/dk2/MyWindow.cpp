//
// Created by DiaLight on 08.07.2024.
//
#include "dk2/MyWindow.h"

#include <patches/logging.h>

#include "dk2/DxDeviceInfo.h"
#include "dk2/DxModeInfo.h"
#include "dk2/MyBmpSaver.h"
#include "dk2/engine/CWindowTest.h"
#include "dk2/engine/WinEventHandlers.h"
#include "dk2/engine/game_engine.h"
#include "dk2/inputs/Event0_winShown7.h"
#include "dk2/utils/AABB.h"
#include "dk2/utils/Pos2i.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "patches/remember_window_location_and_size.h"

void __cdecl dk2::MyWindow_static_destroy() {
    CWindowTest_destroy(&MyWindow_instance.c_window_test);
}

int dk2::MyWindow::collect3dDevices() {
    if (this->pIDirect3D2) {
        this->pIDirect3D2->Release();
        this->pIDirect3D2 = NULL;
    }
    this->d3devCount = 0;
    LPDIRECTDRAW lpdd = ge_dk2dd_get(NULL);
    if (lpdd->QueryInterface(CLSID_IDirect3D2, (LPVOID *) &this->pIDirect3D2) >= 0
        && this->pIDirect3D2->EnumDevices([](GUID FAR *lpGuid, LPSTR lpDeviceDescription,
                                                LPSTR lpDeviceName, LPD3DDEVICEDESC a4, LPD3DDEVICEDESC a5,
                                                LPVOID lpContext) -> HRESULT {
        MyWindow *self = (MyWindow *) lpContext;
        if (self->d3devCount >= 16) return DIENUM_STOP;
        MyD3DevInfo *pInfo = &self->d3devArr[self->d3devCount];
        pInfo->lpGuid = *lpGuid;
        pInfo->lpDeviceDescription = lpDeviceDescription;
        pInfo->lpDeviceName = lpDeviceName;
        pInfo->desc1 = a4;
        pInfo->desc2 = a5;
        ++self->d3devCount;
        return DIENUM_CONTINUE;
    }, this) < 0) {
        this->pIDirect3D2->Release();
        this->pIDirect3D2 = NULL;
    }
    unsigned int *p_fE85_totalDisplayMemory = &this->totalDisplayMemory;
    DDSCAPS caps;
    caps.dwCaps = 0x10000000;
    this->totalDisplayMemory = 0;
    IDirectDraw2 *lpdd2;
    int result = ge_dk2dd_get(NULL)->QueryInterface(CLSID_IDirectDraw2, (LPVOID *) &lpdd2);
    if (result < 0) return result;
    DWORD freeMemory;
    if (lpdd2->GetAvailableVidMem(&caps, (LPDWORD) &this->totalDisplayMemory, &freeMemory) < 0) {
        IDirectDraw2 *lpdd2_ = lpdd2;
        *p_fE85_totalDisplayMemory = 0;
        return lpdd2_->Release();
    }
    unsigned int availVidMem = 2
                               * MyResources_instance.video_settings.display_width
                               * MyResources_instance.video_settings.display_height
                               + *p_fE85_totalDisplayMemory;
    *p_fE85_totalDisplayMemory = availVidMem;
    MyWindow_log_printf(this, "Available Video Memory %dK\n", availVidMem >> 10);
    return lpdd2->Release();
}

BOOL dk2::process_win_inputs() {
    MSG Msg;
    int msg_limit = 2000;
    while (true) {
        if (!PeekMessageA(&Msg, NULL, 0, 0, 1u)) return false;
        if (!msg_limit--) break;
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
    }
    return true;
}

int dk2::MyWindow::prepareScreenEx(
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
        if (g_isGameWindowCreated == 1) {
            setDebugStringFun(debugMsgBox);
            this->zbufferSurf = NULL;
            this->c_window_test.recreate();
            IDirect3D2 *f6D_pIDirect3D2 = this->pIDirect3D2;
            if (f6D_pIDirect3D2) {
                f6D_pIDirect3D2->Release();
                this->pIDirect3D2 = NULL;
            }
            int status;
            dk2wnd_cleanup(&status);
            BullfrogWindow_destroy();
            g_isGameWindowCreated = 0;
        }
        int result = this->createWindow(0);
        if (!result) {
            patch::log::err("Screen Mode %d*%d (%d bpp) create window failed", dwWidth, dwHeight, dwRGBBitCount);
            return 0;
        }
    }
    if(this->last_selected_dd_idx < g_ge_ddraw_device_count) {
        DxDeviceInfo * dev = &g_ge_ddraw_devices[this->last_selected_dd_idx];
        bool found = false;
        for (int ddraw_idx = 0; ddraw_idx < dev->modeListCount; ++ddraw_idx) {
            DxModeInfo *cur = &dev->modeList[ddraw_idx];
            if(cur->dwWidth == dwWidth && cur->dwHeight == dwHeight && cur->dwRGBBitCount == dwRGBBitCount) {
                found = true;
                break;
            }
        }
        if(!found) {
            patch::log::err("Screen Mode %d*%d (%d bpp) is not available", dwWidth, dwHeight, dwRGBBitCount);
            MyWindow_log_printf(this, "Screen Mode %d*%d (%d bpp) is not available\n", dwWidth, dwHeight, dwRGBBitCount);
            for (int ddraw_idx = 0; ddraw_idx < dev->modeListCount; ++ddraw_idx) {
                DxModeInfo* cur = &dev->modeList[ddraw_idx];
                patch::log::dbg("- %dx%d (%d bpp)", cur->dwWidth, cur->dwHeight, cur->dwRGBBitCount);
            }
            return 0;
        }
    }
    for (int i = 0; i < 8; ++i) {
        if (auto *cb = this->WM_ACTIVATE_callbacks[i])
            cb(2, 0, 0, this->WM_ACTIVATE_userData[i]);
    }
    setDebugStringFun(debugMsgBox);
    int screenHardware3D_ = screenHardware3D;
    bool isFullscreen = isWindowed == 0;
    int screenSwap_ = screenSwap;
    this->zbufferSurf = NULL;
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
    if (!cmd_flag_NOSOUND && g_MySound_ptr->v_sub_567210())
        g_MySound_ptr->v_fun_5677D0();
    this->c_window_test.recreate();
    if (isWindowed) {
        int x = 50;
        int y = 50;
        patch::remember_window_location_and_size::patchWinLoc(x, y);
        AABB aabb{
            x, y,
            (int) dwWidth + x, (int) dwHeight + y
        };
        int status;
        if (*this->c_window_test.probably_do_show_window_ev0_7(&status, &aabb) < 0) {
            patch::log::err("Screen Mode %d*%d (%d bpp) show failed", dwWidth, dwHeight, dwRGBBitCount);
            return 0;
        }
        patch::remember_window_location_and_size::resizeWindow(this->c_window_test.hWnd, dwWidth, dwHeight);
    } else {
        int status;
        if (*ge_dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount, initFlags, 0) < 0) {
            patch::log::err("Screen Mode %d*%d (%d bpp) dk2dd_init 1 failed", dwWidth, dwHeight, dwRGBBitCount);
            process_win_inputs();
            if (*ge_dk2dd_init(&status, dwWidth, dwHeight, dwRGBBitCount, initFlags, 0) < 0) {
                patch::log::err("Screen Mode %d*%d (%d bpp) dk2dd_init 2 failed", dwWidth, dwHeight, dwRGBBitCount);
                return 0;
            }
        }
    }
    if (!cmd_flag_NOSOUND) {
        if (g_MySound_ptr->v_sub_567210())
            g_MySound_ptr->v_fun_5677E0();
        else
            g_MySound_ptr->v_set_number_of_channels(
                    MyResources_instance.soundCfg.numberOfChannels);
        MyResources_instance.soundCfg.readOrCreate();
    }
    this->isWindowed = isWindowed;
    this->dwWidth = dwWidth;
    this->dwHeight = dwHeight;
    this->dwRGBBitCount = dwRGBBitCount;
    this->_prepareScreen_a6 = screenSwap;
    this->_prepareScreen_a7 = screenHardware3D_;
    this->f18 = 0;
    this->collect3dDevices();
    this->colors.init(NULL);
    setDebugStringFun(MyWindow_static_559050_parse);
    if (MyResources_instance.video_settings.zbuffer_bitnes == 16) {
        if (!this->createZBufferSurf(0x10u) && !this->createZBufferSurf(0x20u))
            this->createZBufferSurf(0x18u);
    } else if (MyResources_instance.video_settings.zbuffer_bitnes == 32
               && !this->createZBufferSurf(0x20u)
               && !this->createZBufferSurf(0x18u)) {
        this->createZBufferSurf(0x10u);
    }
    // move mouse to center
    Pos2i mousePos {
        (int) this->dwWidth / 2,
        (int) this->dwHeight / 2
    };
    MyInputManagerCb_static_setMousePos(&mousePos);
    // direct invoke mouse updater
    AABB updateMousePos {0, 0, (int) dwWidth, (int) dwHeight};
    MyInputManagerCb_static_updateMouse(&updateMousePos);
    for (int i = 0; i < 8; ++i) {
        if (auto * cb = this->WM_ACTIVATE_callbacks[i]) {
            cb(3, 0, 0, this->WM_ACTIVATE_userData[i]);
        }
    }
    MyResources_instance.video_settings.writeGuidIndexIsDefault(0);
    MyResources_instance.video_settings.writeGuidIndexVerifiedWorking(1);
    HWND HWindow = getHWindow();
    ij_ImmAssociateContext(HWindow, NULL);
    patch::log::dbg("prepareScreen %dx%d bpp=%d w=%d ssw=%d hw=%d success",
           dwWidth, dwHeight, dwRGBBitCount, isWindowed,
           screenSwap, screenHardware3D);
    return 1;
}

int dk2::MyWindow::prepareScreen2() {
    if (this->dwRGBBitCount == 8) {
        PALETTEENTRY dst[256];
        readPaletteEntry(dst, 0, 256);
        this->prepareScreenEx(
                this->dwWidth, this->dwHeight,
                this->dwRGBBitCount, this->isWindowed,
                this->_prepareScreen_a6,
                1);
        updatePalette(dst, 0, 256);
        this->colors.init(dst);
        return this->collect3dDevices();
    } else {
        this->prepareScreenEx(
                this->dwWidth, this->dwHeight,
                this->dwRGBBitCount, this->isWindowed,
                this->_prepareScreen_a6,
                1);
        return this->collect3dDevices();
    }
}

namespace dk2 {

    bool getNextResolution(int & w, int & h) {
        switch (w) {
        case 512: w = 400; h = 300; return true;
        case 640: w = 512; h = 384; return true;
        case 800: w = 640; h = 480; return true;
        case 1024: w = 800; h = 600; return true;
        case 1280: w = 1024; h = 768; return true;
        case 1600: w = 1280; h = 1024; return true;
        }
        return false;
    }

}

int dk2::MyWindow_prepareWithSettings(int * pHardware3d) {
    int screen_swap = MyResources_instance.video_settings.screen_swap;
    int dwRGBBitCount = MyResources_instance.video_settings.display_bitnes;
    int display_width = MyResources_instance.video_settings.display_width;
    int display_height = MyResources_instance.video_settings.display_height;
    int isFullscreen = MyResources_instance.video_settings.isWindowed;
    if (MyResources_instance.video_settings.dup_selected_3D_engine) {
        MyResources_instance.video_settings.setSelected3dEngine(
            MyResources_instance.video_settings.dup_selected_3D_engine);
        MyResources_instance.video_settings.dup_selected_3D_engine = 0;
    } else {
        MyResources_instance.video_settings.dup_selected_3D_engine = MyResources_instance.video_settings.selected_3D_engine;
    }
    if (MyResources_instance.video_settings.selected_3D_engine == 4) {
        *pHardware3d = 0;
        screen_swap = 0;
    }
    MyWindow_instance.recreateOnPrepare = 1;
    while (true) {
        if (MyWindow_instance.prepareScreenEx(
                display_width,
                display_height,
                dwRGBBitCount,
                isFullscreen,
                screen_swap,
                *pHardware3d)) return 1;
        if(!getNextResolution(display_width, display_height)) break;
    }
    if (MyWindow_instance.prepareScreenEx(
            640, 480, 16,
            isFullscreen, screen_swap,
            *pHardware3d)) return 1;
    return 0;
}

namespace dk2 {

    void inline_selectDrawEngine(dk2::MyWindow *window);

}

int dk2::MyWindow::init() {
    inline_selectDrawEngine(this);
    int status;
    if (*MyInputManagerCb_static_initKeyInputs(&status) < 0) {
        patch::log::err("failed to call MyInputManagerCb_static_initKeyInputs()");
        return 0;
    }
    if (*MyInputManagerCb_static_initCursorInputs(&status) < 0) {
        patch::log::err("failed to call MyInputManagerCb_static_initCursorInputs()");
        return 0;
    }
    if (!this->createWindow(1)) {
        patch::log::err("failed to call this->createWindow()");
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
    setCustomDefWindowProcA(myCustomDefWindowProcA);
    WinEventHandlers_instance.addHandler(0, static_MyWindow_Event07_cb, this);
    this->fE71 = 0;
    this->fE75 = 0;
    this->recreateRequest = 0;
    this->doCallInit3d = 0;
    this->moonAge = calc_moon_age();
    this->f0 = 1;
    this->fF51 = 0;
    return 1;
}

void dk2::MyWindow::release() {
    int status;
    if (g_isGameWindowCreated == 1) {
        setDebugStringFun(debugMsgBox);
        this->zbufferSurf = NULL;
        this->c_window_test.recreate();
        if (IDirect3D2* d3d = this->pIDirect3D2) {
            d3d->Release();
            this->pIDirect3D2 = NULL;
        }
        dk2wnd_cleanup(&status);
        BullfrogWindow_destroy();
        g_isGameWindowCreated = 0;
    }
    MyInputManagerCb_instance.static_releaseMouse();
    MyInputManagerCb_instance.static_releaseKeyboard();
    WinEventHandlers_instance.removeHandler(0, static_MyWindow_Event07_cb, 0);
    if (MyLogger_isInitialized(&this->logObj_err))
        MyLogger_destroy(&status, &this->logObj_err);
    if (MyLogger_isInitialized(&this->logObj_out))
        MyLogger_destroy(&status, &this->logObj_out);
    this->f0 = 0;
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

void dk2::MyWindow::removeWmActivateCallback(void *ptr) {;
    for (int i = 0; i < 8; ++i) {
        if (patch::try_unpack_jmp(this->WM_ACTIVATE_callbacks[i]) != patch::try_unpack_jmp(ptr)) continue;
        this->WM_ACTIVATE_callbacks[i] = NULL;
        this->WM_ACTIVATE_userData[i] = NULL;
        return;
    }
}

int dk2::MyWindow::selectSurfToRender() {
    MyDdSurfaceEx *pSurf;
    if ( this->isWindowed )
        pSurf = this->c_window_test.getCurOffScreenSurf();
    else
        pSurf = g_pCurOffScreen;

    int status;
    if ( *MyDdSurfaceEx_resolveDesc(&status, pSurf, NULL) < 0 )
        return 0;

    MyDdSurfaceEx *CurOffScreenSurf;
    if ( this->isWindowed )
        CurOffScreenSurf = this->c_window_test.getCurOffScreenSurf();
    else
        CurOffScreenSurf = g_pCurOffScreen;

    MySurface_copyFromSurf(&this->surf_desc, CurOffScreenSurf);
    setDrawSurface(&this->surf_desc);
    this->surfSelected = 1;
    return 1;
}

int dk2::MyWindow::getSurf_unlock() {
    int result = this->surfSelected;
    if (!result) return 0;

    if (this->isWindowed) {
        result = MyDdSurfaceEx_unlock(this->c_window_test.getCurOffScreenSurf());
    } else {
        result = MyDdSurfaceEx_unlock(g_pCurOffScreen);
    }
    this->surfSelected = 0;
    return result;
}

dk2::MyDdSurfaceEx *dk2::MyWindow::getCurOffScreenSurf() {
    if (this->isWindowed)
        return this->c_window_test.getCurOffScreenSurf();
    else
        return g_pCurOffScreen;
}

int dk2::MyWindow::takeScreenshot() {
    MyDdSurfaceEx* CurOffScreenSurf;
    if (this->isWindowed)
        CurOffScreenSurf = this->c_window_test.getCurOffScreenSurf();
    else
        CurOffScreenSurf = g_pCurOffScreen;

    char bmpSaverBuf[sizeof(MyBmpSaver)];
    auto &bmpSaver = *(MyBmpSaver *) bmpSaverBuf;
    bmpSaver.constructor();

    char dst[1024];
    BYTE* PalleteEntry;
    if (this->dwRGBBitCount == 8)
        PalleteEntry = (BYTE*) readPaletteEntry(dst, 0, 256);
    else
        PalleteEntry = NULL;

    int status;
    if (!fs_fileExists("SCRSHOTS") && *fs_createDirectory(&status, "SCRSHOTS") < 0)
        return 0;

    int v5 = 0;
    char Buffer[260];
    if (MyResources_instance.gameCfg.f12C) {
        int v6 = MyResources_instance.gameCfg.lastShotIdx;
        if (MyResources_instance.gameCfg.lastShotIdx) {
            sprintf(Buffer, "%s\\SHOT%04d.BMP", "SCRSHOTS", MyResources_instance.gameCfg.lastShotIdx);
            MyResources_instance.gameCfg.lastShotIdx = v6 + 1;
        } else {
            do
                sprintf(Buffer, "%s\\SHOT%04d.BMP", "SCRSHOTS", v6++);
            while (fs_fileExists(Buffer));
            MyResources_instance.gameCfg.lastShotIdx = v6;
        }
    } else {
        do
            sprintf(Buffer, "%s\\SHOT%04d.BMP", "SCRSHOTS", v5++);
        while (fs_fileExists(Buffer));
    }

    LPVOID lpSurface;
    if (*MyDdSurfaceEx_resolveDesc(&status, CurOffScreenSurf, &lpSurface) < 0)
        return 1;

    MySurface surf;
    surf.copySurfFrom(CurOffScreenSurf);
    bmpSaver.save(&status, Buffer, &surf, PalleteEntry);
    MyDdSurfaceEx_unlock(CurOffScreenSurf);
    return 1;
}

int dk2::MyWindow::createZBufferSurf(uint32_t dwMipMapCount) {
    int dwWidth = this->dwWidth;
    int dwHeight = this->dwHeight;
    DDSURFACEDESC desc;
    memset(&desc, 0, sizeof(desc));
    static_assert(sizeof(DDSURFACEDESC) == 108);
    desc.dwSize = sizeof(DDSURFACEDESC);
    desc.dwFlags = 0x47;
    static_assert((DDSCAPS_ZBUFFER | DDSCAPS_VIDEOMEMORY) == 0x24000);
    desc.ddsCaps.dwCaps = DDSCAPS_ZBUFFER | DDSCAPS_VIDEOMEMORY;
    desc.dwWidth = dwWidth;
    desc.dwHeight = dwHeight;
    desc.dwMipMapCount = dwMipMapCount;
    LPDIRECTDRAW lpdd = ge_dk2dd_get(NULL);
    LPDIRECTDRAWSURFACE *p_f275_zbufferSurf = &this->zbufferSurf;
    if ( lpdd->CreateSurface(&desc, &this->zbufferSurf, NULL) >= 0 ) {
        MyDdSurfaceEx *CurOffScreenSurf;
        if ( this->isWindowed )
            CurOffScreenSurf = this->c_window_test.getCurOffScreenSurf();
        else
            CurOffScreenSurf = g_pCurOffScreen;
        if ( CurOffScreenSurf ) {
            MyDdSurfaceEx *offscreen = this->isWindowed ? this->c_window_test.getCurOffScreenSurf() : g_pCurOffScreen;
            LPDIRECTDRAWSURFACE lpddsurf = MyDdSurface_addRef(&offscreen->dd_surf, 0);
            if ( lpddsurf ) {
                if ( lpddsurf->AddAttachedSurface(*p_f275_zbufferSurf) >= 0 )
                    return 1;
            }
        }
        (*p_f275_zbufferSurf)->Release();
    }
    *p_f275_zbufferSurf = NULL;
    return 0;
}

int dk2::MyWindow::handleError(char *a2_file, int a3_line, const char *a4_text, char *a5_text) {
    if (g_isHandlingError)
        return 0;
    g_isHandlingError = 1;
    ++this->f505;
    int status;
    if (!MyLogger_isInitialized(&this->logObj_err))
        MyLogger_init(&status, &this->logObj_err, "ERROR.LOG", 0xF);
    if (MyLogger_isInitialized(&this->logObj_err)) {
        char Buffer[1024];
        sprintf(Buffer, "%s[%d][GT %d]: %s: %s\n", path_getBasename(a2_file), a3_line, g_gameTick_758044, a4_text, a5_text);
        MyLogger_printf(&status, &this->logObj_err, Buffer);
    }
    if (this->f299) {
        g_isHandlingError = 0;
        return 0;
    } else {
        if (this->isTurnErrors) {
            status = this->surfSelected;
            if (status) {
                MyDdSurfaceEx* CurOffScreenSurf;
                if (this->isWindowed)
                    CurOffScreenSurf = this->c_window_test.getCurOffScreenSurf();
                else
                    CurOffScreenSurf = g_pCurOffScreen;
                MyDdSurfaceEx_unlock(CurOffScreenSurf);
                this->surfSelected = 0;
            }
            this->static_listeners.onKeyboardAction = NULL;
            this->static_listeners.onMouseAction = NULL;
            this->static_listeners.onWindowMsg = NULL;
            this->static_listeners.onKeyboardActionWithCtrl = NULL;
            this->static_listeners.onMouseActionWithCtrl = NULL;
            this->static_listeners.onKeyboardAction = (int(__cdecl*)(int, int, CComponent*)) sub_5594E0;
            this->f291 = 0;
            do {
                this->displayError(a2_file, a3_line, a4_text, a5_text);
                MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                    &this->static_listeners,
                    0,
                    (CComponent*) this,
                    0);
            } while (!this->f291);
            if (status) {
                MyDdSurfaceEx* v9_surf = this->isWindowed ? this->c_window_test.getCurOffScreenSurf() : g_pCurOffScreen;
                if (*MyDdSurfaceEx_resolveDesc(&status, v9_surf, NULL) >= 0) {
                    MyDdSurfaceEx* offscreen;
                    if (this->isWindowed)
                        offscreen = this->c_window_test.getCurOffScreenSurf();
                    else
                        offscreen = g_pCurOffScreen;
                    MySurface_copyFromSurf(&this->surf_desc, offscreen);
                    setDrawSurface(&this->surf_desc);
                    this->surfSelected = 1;
                }
            }
        }
        g_isHandlingError = 0;
        return this->f295;
    }
}

void dk2::MyWindow::displayError(char *a2_file, int a3_line, const char *a4_text, char *a5_text2) {
    this->surf_Blt();
    MyDdSurfaceEx* CurOffScreenSurf;
    if (this->isWindowed)
        CurOffScreenSurf = this->c_window_test.getCurOffScreenSurf();
    else
        CurOffScreenSurf = g_pCurOffScreen;
    int status;
    if (*MyDdSurfaceEx_resolveDesc(&status, CurOffScreenSurf, NULL) >= 0) {
        MyDdSurfaceEx* v7_offscreen;
        if (this->isWindowed)
            v7_offscreen = this->c_window_test.getCurOffScreenSurf();
        else
            v7_offscreen = g_pCurOffScreen;
        MySurface_copyFromSurf(&this->surf_desc, v7_offscreen);
        setDrawSurface(&this->surf_desc);
        this->surfSelected = 1;
        char Buffer[256];
        sprintf(Buffer, "%s(%d)[GT %d]: %s at line %d", a4_text, this->f505, g_gameTick_758044, path_getBasename(a2_file), a3_line);
        static_MyNBitTexture_f30(0, 0, Buffer, this->colors.colorWhite);
        static_MyNBitTexture_f30(0, 12, a5_text2, this->colors.colorWhite);
        const char* v9_turnErrors = "OFF";
        if (!this->isTurnErrors)
            v9_turnErrors = "ON";
        sprintf(Buffer, "[F10] Continue  [ESC] Quit  [SPACE] Debug  [E] Turn Errors %s", v9_turnErrors);
        static_MyNBitTexture_f30(0, 24, Buffer, this->colors.colorWhite);
        if (this->surfSelected) {
            MyDdSurfaceEx* offscreen;
            if (this->isWindowed)
                offscreen = this->c_window_test.getCurOffScreenSurf();
            else
                offscreen = g_pCurOffScreen;
            MyDdSurfaceEx_unlock(offscreen);
            this->surfSelected = 0;
        }
    }
    this->prepareScreen();
}

