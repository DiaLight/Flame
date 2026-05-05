//
// Created by DiaLight on 1/3/2026.
//
#include "dk2/engine/DdModeList.h"
#include "WinEventHandlers.h"
#include "dk2/dk2_memory.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "game_engine.h"
#include "gog_patch.h"
#include "patches/micro_patches.h"
#include "patches/replace_mouse_dinput_to_user32.h"
#include "patches/show_wireframe.h"
#include "patches/use_wheel_to_zoom.h"


namespace dk2 {

    LRESULT CALLBACK BullfrogWindow_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {  // fullscreen proc
        patch::replace_mouse_dinput_to_user32::emulate_dinput_from_user32(hWnd, Msg, wParam, lParam);
        patch::use_wheel_to_zoom::window_proc(hWnd, Msg, wParam, lParam);
        patch::fix_keyboard_state_on_alt_tab::window_proc(hWnd, Msg, wParam, lParam);
        patch::show_wireframe::window_proc(hWnd, Msg, wParam, lParam);
        if(gog::BullfrogWindow_proc_patch::window_proc(hWnd, Msg, wParam, lParam))
            return DefWindowProcA(hWnd, Msg, wParam, lParam);
        switch (Msg) {
        case WM_ACTIVATEAPP:
            g_isWindowActivated = wParam != 0;
            break;
        case WM_SYSCOMMAND:
            switch ( wParam ) {
            case 0xF100:
                return 0;
            default:
                break;
            }
            break;
        case WM_CLOSE:
            setAppExitStatus(1);
            return 0;
        case WM_ACTIVATE:
            if ( hWnd == getHWindow() ) {
                // WA_INACTIVE 0  // Deactivated
                // WA_ACTIVE 1  // by some method
                // WA_CLICKACTIVE 2  // by a mouse click
                int isActivated = wParam == 1 || wParam == 2;
                setAppActivatedStatus(isActivated);
                callWinEvent_ev0_ty4(isActivated);
            }
            break;
        }
        if(patch::hide_mouse_cursor_in_window::window_proc(hWnd, Msg, wParam, lParam)) return TRUE;

        if (auto CustomDefWindowProcA = (CustomDefWindowProcA_t) getCustomDefWindowProcA())
            CustomDefWindowProcA(hWnd, Msg, wParam, lParam);
        return DefWindowProcA(hWnd, Msg, wParam, lParam);
    }

    void BullfrogWindow_registerClass() {
        static bool s_registered = false;
        if (s_registered) return;
        s_registered = true;

        WNDCLASSA wndClass;
        memset(&wndClass, 0, sizeof(wndClass));

        wndClass.style = 3;
        wndClass.lpfnWndProc = BullfrogWindow_proc;
        wndClass.cbClsExtra = 0;
        wndClass.cbWndExtra = 0;
        wndClass.hInstance = getHInstance();
        if (getLibIconName()) {
            wndClass.hIcon = LoadIconA(getHInstance(), getLibIconName());
        }
        wndClass.hbrBackground = (HBRUSH) GetStockObject(4);
        wndClass.lpszMenuName = NULL;
        sprintf(g_bullfrogClassName, "_BullfrogLibScreen");
        wndClass.lpszClassName = g_bullfrogClassName;
        RegisterClassA(&wndClass);
    }

    bool g_isBullfrogWindowCreated = false;


    int *DdModeList_collect(int *pstatus, int useWindowContext, HWND hWnd, GUID *lpGUID) {
        int status;
        LPDIRECTDRAW lpDD = NULL;
        if (*ge_createDirectDrawObject(&status, lpGUID, &lpDD) < 0)
            return *pstatus = -1, pstatus;
        DdModeList::instance.constructor();
        DdModeList::instance.collect(pstatus, lpDD, useWindowContext, hWnd);
        lpDD->Release();
        return pstatus;
    }

    int *__cdecl BullfrogWindow_create(int *pstatus, GUID *lpGUID, int aBool, HWND hWndParent, HWND hWnd) {
        if (g_isBullfrogWindowCreated) return *pstatus = 0, pstatus;
        setHWindow(hWndParent);
        if (!hWndParent) {
            BullfrogWindow_registerClass();
            HWND hWindow = CreateWindowExA(
                8u,
                g_bullfrogClassName,
                getWindowName(),
                0x80080000, 0, 0,
                GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN),
                NULL, NULL, getHInstance(), NULL);
            g_hBullfrogWindow = hWindow;
            if (!hWindow) return *pstatus = -1, pstatus;
            setHWindow(hWindow);
        }
        int status;
        if (*DdModeList_collect(&status, aBool, hWnd, lpGUID) < 0) {
            return *pstatus = -1, pstatus;
        }
        setSelectedDDGuid(lpGUID);
        g_isBullfrogWindowCreated = true;
        return *pstatus = 0, pstatus;
    }

    void BullfrogWindow_destroy() {
        if (g_isBullfrogWindowCreated) {
            g_isBullfrogWindowCreated = false;
            ge_ddReleaseSurfaces();
            ge_dk2dd_destroy();
            if (g_hBullfrogWindow)
                DestroyWindow(g_hBullfrogWindow);
            g_hBullfrogWindow = NULL;
        }
        DdModeList::instance.destroy();
    }

    int *__cdecl copyToFullscreenSurf(int *pstatus, int a2_flags) {
        int hresult;
        int v2_flags = a2_flags ^ 1;
        if ((g_primarySurf.dd_surf.flags & 2) != 0) {
            callWinEvent_ev1_ty2(g_pCurOffScreen);
            static_assert(DDERR_SURFACEBUSY == 0x887601AE);
            static_assert(DDERR_WASSTILLDRAWING == 0x8876021C);
            while (true) {
                hresult = g_primarySurf.dd_surf.dd_surface->Flip(g_pCurOffScreen->dd_surf.dd_surface, v2_flags);
                if(hresult == DDERR_SURFACEBUSY) continue;
                if(hresult == DDERR_WASSTILLDRAWING) continue;
                break;
            }
            callWinEvent_ev1_ty3(g_pCurOffScreen);
        } else {
            callWinEvent_ev1_ty0(g_pCurOffScreen);
            if ((g_primarySurf.dd_surf.flags & 0x10) != 0) {
                DDBLTFX DDBltFx;
                memset(&DDBltFx, 0, sizeof(DDBltFx));
                static_assert(sizeof(DDBLTFX) == 100);
                DDBltFx.dwSize = sizeof(DDBLTFX);
                HWND HWindow = getHWindow();
                RECT Rect;
                GetClientRect(HWindow, &Rect);
                POINT Point {0, 0};
                ClientToScreen(HWindow, &Point);
                Rect.top += Point.y;
                Rect.left += Point.x;
                Rect.right += Point.x;
                Rect.bottom += Point.y;
                hresult = g_primarySurf.dd_surf.dd_surface->Blt(
                    &Rect, g_pCurOffScreen->dd_surf.dd_surface,
                    NULL, 0x1000000, &DDBltFx);
            } else if (g_isSurfModeX) {
                Obj79D1C0_instance.pPrimaryAttachedSurf->BltFast(0, 0, g_pCurOffScreen->dd_surf.dd_surface, NULL, 16 * v2_flags);
                hresult = g_primarySurf.dd_surf.dd_surface->Flip(Obj79D1C0_instance.pPrimaryAttachedSurf, v2_flags);
            } else {
                hresult = g_primarySurf.dd_surf.dd_surface->BltFast(0, 0, g_pCurOffScreen->dd_surf.dd_surface, NULL, 16 * v2_flags);
            }
            callWinEvent_ev1_ty1(g_pCurOffScreen);
        }
        static_assert(DDERR_SURFACELOST == 0x887601C2);
        if (hresult == DDERR_SURFACELOST) {
            MyDdSurfaceEx_restoreSurf_if_unk(&g_primarySurf);
            MyDdSurfaceEx_restoreSurf_if_unk(g_pCurOffScreen);
        }
        return *pstatus = hresult, pstatus;
    }

    BOOL __cdecl MyDdSurfaceEx_restoreSurf_if_unk(MyDdSurfaceEx *a1) {
        static_assert(DDERR_SURFACELOST == 0x887601C2);
        HRESULT hresult;
        hresult = a1->dd_surf.dd_surface->IsLost();
        if (hresult != DDERR_SURFACELOST) return true;
        hresult = a1->dd_surf.dd_surface->Restore();
        return hresult == DD_OK;
    }

}
