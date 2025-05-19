//
// Created by DiaLight on 25.08.2024.
//
#include <Windows.h>
#include "dk2/MyMouseUpdater.h"
#include "dk2/Event0_winShown7.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/replace_mouse_dinput_to_user32.h"
#include "patches/micro_patches.h"
#include "patches/use_wheel_to_zoom.h"
#include "gog_patch.h"
#if __has_include(<dk2_research.h>)
   #include <dk2_research.h>
#endif

int __cdecl dk2::getCustomDefWindowProcA() {
    return customDefWindowProcA;
}
typedef LRESULT (__stdcall *CustomDefWindowProcA_t)(HWND, UINT, WPARAM, LPARAM);

LRESULT dk2::CWindowTest_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {  // windowed proc
#if __has_include(<dk2_research.h>)
    research::windowProc(hWnd, Msg, wParam, lParam);
#endif

    // patch::BEFORE_WINDOW_PROC
    patch::remember_window_location_and_size::window_proc(hWnd, Msg, wParam, lParam);
    patch::replace_mouse_dinput_to_user32::emulate_dinput_from_user32(hWnd, Msg, wParam, lParam);
    patch::use_wheel_to_zoom::window_proc(hWnd, Msg, wParam, lParam);
    patch::fix_keyboard_state_on_alt_tab::window_proc(hWnd, Msg, wParam, lParam);
    patch::bring_to_foreground::window_proc(hWnd, Msg, wParam, lParam);
    if (!patch::fix_close_window::window_proc(hWnd, Msg, wParam, lParam)) return 0;
    switch(Msg) {
        case WM_ACTIVATE:
            g_isNeedBlt_fullscr = wParam != 0;
            break;
        case WM_SYSCOMMAND: {
            switch ( wParam ) {
                case 0xF090u:
                case 0xF093u:
                case 0xF100u:
                case 0xF160u:
                case 0xF163u:
                    return 0;
                default:
                    break;
            }
            break;
        }
        case WM_MOUSEMOVE: {
            if(!patch::replace_mouse_dinput_to_user32::enabled) {
                Pos2i pos;
                pos.x = LOWORD(lParam);
                pos.y = HIWORD(lParam);
                MyInputManagerCb_static_setMousePos(&pos);
            }
            break;
        }
    }
    if(patch::hide_mouse_cursor_in_window::window_proc(hWnd, Msg, wParam, lParam)) return TRUE;

    if (auto CustomDefWindowProcA = (CustomDefWindowProcA_t) getCustomDefWindowProcA())
        return CustomDefWindowProcA(hWnd, Msg, wParam, lParam);
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

LRESULT dk2::BullfrogWindow_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {  // fullscreen proc
    patch::replace_mouse_dinput_to_user32::emulate_dinput_from_user32(hWnd, Msg, wParam, lParam);
    patch::use_wheel_to_zoom::window_proc(hWnd, Msg, wParam, lParam);
    patch::fix_keyboard_state_on_alt_tab::window_proc(hWnd, Msg, wParam, lParam);
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
                int isActivated;
                isActivated = wParam == 1 || wParam == 2;
                setAppActivatedStatus(isActivated);

                Event0_winShown7 v7;
                v7.eventType = 4;
                v7.width = isActivated;
                WinEventHandlers_instance.callList(0, (int)&v7);
            }
            break;
    }
    if(patch::hide_mouse_cursor_in_window::window_proc(hWnd, Msg, wParam, lParam)) return TRUE;

    if (auto CustomDefWindowProcA = (CustomDefWindowProcA_t) getCustomDefWindowProcA())
        CustomDefWindowProcA(hWnd, Msg, wParam, lParam);
    return DefWindowProcA(hWnd, Msg, wParam, lParam);
}

