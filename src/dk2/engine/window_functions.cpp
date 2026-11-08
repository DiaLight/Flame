//
// Created by DiaLight on 12/10/2025.
//
#include "WinEventHandlers.h"
#include "dk2/MyDxDevice.h"
#include "dk2/dk2_memory.h"
#include "dk2/inputs/InputSurf.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "game_engine.h"
#include "gog_exports.h"
#include "gog_patch.h"
#include "patches/opengl/opengl_patch.h"
#include "patches/logging.h"


dk2::MyDdSurfaceEx zeroSurf() {
    return {
        {
            0, 0, 0, 0,
            0, 0, 0, 0,
            0,
            0, 0, 0, 0,
            0, 0,
            NULL
        },
        {
            {
                0, 0, 0, 0, 0, 0
            },
            NULL, 0, 0, 0
        }

    };
}

namespace dk2 {

    HINSTANCE g_hInstance = NULL;
    void setHInstance(HINSTANCE hInst) {
        g_hInstance = hInst;
    }
    HINSTANCE getHInstance() {
        return g_hInstance;
    }


    char g_bullfrogClassName[260];

    char g_windowName[64];
    void setWindowName(int *pstatus, const char *name) {
        strncpy(g_windowName, name ? name : "Bullfrog", 64);
        *pstatus = 0;
    }
    char *getWindowName() {
        return g_windowName;
    }


    int16_t g_libIconName = 0;
    LPCSTR getLibIconName() {
        return (LPCSTR) g_libIconName;
    }
    int *setLibIconName(int *pstatus, __int16 a2) {
        g_libIconName = a2;
        return *pstatus = 0, pstatus;
    }


    CustomDefWindowProcA_t g_customDefWindowProcA = NULL;
    CustomDefWindowProcA_t getCustomDefWindowProcA() {
        return g_customDefWindowProcA;
    }
    void setCustomDefWindowProcA(CustomDefWindowProcA_t proc) {
        g_customDefWindowProcA = proc;
    }


    HWND g_dd_hWnd = NULL;
    void setHWindow(HWND hWnd) {
        g_dd_hWnd = hWnd;
    }
    HWND getHWindow() {
        return g_dd_hWnd;
    }

    HWND g_hWnd = NULL;

    HWND g_hBullfrogWindow = NULL;

    GUID *g_selectedDDGuid = NULL;
    void setSelectedDDGuid(GUID *guid) {
        g_selectedDDGuid = guid;
    }

    LPDIRECTDRAW ge_lpSurfaceDD = NULL;
    void setSurfaceDD(LPDIRECTDRAW lpdd) {
        ge_lpSurfaceDD = lpdd;
    }

    MyDdSurfaceEx g_offScreen = zeroSurf();
    MyDdSurfaceEx *g_pCurOffScreen = NULL;
    void setCurOffScreen(MyDdSurfaceEx *surf) {
        g_pCurOffScreen = surf ? surf : &g_offScreen;
    }

    MyDdSurfaceEx g_primarySurf = zeroSurf();

    LPDIRECTDRAWPALETTE g_lpDDPalette = NULL;
    LPDIRECTDRAWCLIPPER g_lpDDClipper = NULL;

    Obj79D1C0 Obj79D1C0_instance {
            .f0=0, .f1=0, .f2=0, .f3=0, .f4=0, .f10=0, .pPrimaryAttachedSurf=NULL, .mySurf_unused = {
                    {0, 0, 0, 0, 0, 0},
                    NULL, {0, 0}, 0
            }
    };

}

dk2::MyDdSurfaceEx *dk2::InputSurf::getPrimarySurf() {
    return &g_primarySurf;
}

dk2::MyDdSurfaceEx *dk2::InputSurf::getCurOffScreen() {
    return g_pCurOffScreen;
}

unsigned int dk2::InputSurf::isSurfaceFlag() {
    return (g_primarySurf.dd_surf.flags >> 1) & 1;
}

int *__cdecl dk2::ge_createDirectDrawObject(int *pstatus, GUID *lpGUID, LPDIRECTDRAW *lplpDD) {
    if(patch::opengl_patch::enabled) {
       patch::log::dbg("should not happen");
       throw std::exception("should not happen");
    }
    HRESULT hresult;
    if(*o_gog_enabled) {
        hresult = fake_DirectDrawCreate(lpGUID, lplpDD, NULL);
    } else {
        hresult = DirectDrawCreate(lpGUID, lplpDD, NULL);
    }
    if (hresult != DD_OK) return *pstatus = -1, pstatus;
    if (g_hBullfrogWindow) setHWindow(g_hBullfrogWindow);
    return *pstatus = 0, pstatus;
}

namespace dk2 {

    void callActivateCallbacks(WPARAM wParam) {
        if ( (WORD) wParam ) {
            for (int i = 0; i < 8; ++i) {
                if (MyWindow_instance.WM_ACTIVATE_callbacks[i])
                    MyWindow_instance.WM_ACTIVATE_callbacks[i](0, 0, 0, MyWindow_instance.WM_ACTIVATE_userData[i]);
            }
            MyWindow_instance.fE71 = 1;
            if ( MyWindow_instance.fE75 ) {
                MyWindow_instance.fE75 = 0;
                MyWindow_instance.recreateRequest = 1;
            }
        } else {
            for (int i = 0; i < 8; ++i) {
                if ( MyWindow_instance.WM_ACTIVATE_callbacks[i] )
                    MyWindow_instance.WM_ACTIVATE_callbacks[i](1, 0, 0, MyWindow_instance.WM_ACTIVATE_userData[i]);
            }
            MyWindow_instance.fE75 = 1;
            MyWindow_instance.fE71 = 0;
        }
    }

}

LRESULT dk2::myCustomDefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch (Msg) {
    case WM_ACTIVATE:
    case WM_ACTIVATEAPP:
    case WM_NCACTIVATE: {
        callActivateCallbacks(wParam);
        break;
    }
    case WM_CHAR: {
        char mbs[4];
        *(uint32_t *) mbs = (uint32_t) wParam;
        wchar_t wcs[2] {};
        if ( MultiByteToWideChar(
                0, 0,
                mbs, -1,
                (LPWSTR) wcs, 2
                ) > 0 ) MyInputManagerCb_static_windowMsgW(WM_CHAR, *(uint32_t *) wcs);
        break;
    }
    case WM_IME_SETCONTEXT: return 0;
    case (WM_USER + 0x10): MyInputManagerCb_static_windowMsgW(0x102, wParam); break;
    default: break;
    }
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

HINSTANCE dk2::MyDxDevice::getHInstance() {
    HINSTANCE result = (HINSTANCE) this->hInstance;
    if ( result == (HINSTANCE)-1 )
        return dk2::getHInstance();
    return result;
}

void __cdecl dk2::dk2wnd_cleanup(int *pstatus) {
    ge_ddReleaseSurfaces();
    ge_dk2dd_destroy();
    *pstatus = 0;
}

void __cdecl dk2::ge_showMessageBox(HWND hWnd, const CHAR *lpText, const CHAR *lpCaption, UINT uType) {
    if ( g_dk2dd )
        g_dk2dd->FlipToGDISurface();
    if ( g_hWnd )
        SetWindowPos(g_hWnd, HWND_NOTOPMOST, 0, 0, 0, 0, 3u);
    MessageBoxA(hWnd, lpText, lpCaption, uType);
    if ( g_hWnd )
        SetWindowPos(g_hWnd, HWND_TOPMOST, 0, 0, 0, 0, 3u);
}

int *dk2::DxDevice_updateCoopLevelAndSignal_ev5(int *pstatus, MyDxDevice *dev) {
    if (dev) {
        int status;
        dev->updateCoopLevel_acquire(&status);
        if (status >= 0 && status != 0x4FFE0002) {  // status >= 0 && Acquire != S_FALSE  // S_FALSE if the device was already acquired
            callWinEvent_ev5_ty11(dev);  // just acquired
        }
        return *pstatus = status, pstatus;
    } else {
        return *pstatus = 0x4FFE0002, pstatus;
    }
}

void __cdecl dk2::updatePalette(PALETTEENTRY *entries, uint32_t start, uint32_t count) {
    LPDIRECTDRAWPALETTE lpDDPalette_ = g_lpDDPalette;
    memcpy(&g_paletteEntries[start], entries, 4 * count);
    if (g_lpDDPalette != NULL) {
        if (g_primarySurf.dd_surf.dd_surface)
            lpDDPalette_->SetEntries(0, start, count, entries);
    }
}

void *__cdecl dk2::readPaletteEntry(void *dst, int idx, int count) {
    if ( g_lpDDPalette ) {
        if ( !g_lpDDPalette->GetEntries(0, idx, count, &g_paletteEntries[idx]) ) {
            memcpy(dst, &g_paletteEntries[idx], 4 * count);
            return dst;
        }
    } else {
        memcpy(dst, &g_paletteEntries[idx], 4 * count);
    }
    return dst;
}

