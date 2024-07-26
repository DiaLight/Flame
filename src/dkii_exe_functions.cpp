//
// Created by DiaLight on 01.07.2024.
//
#include "dk2/MyGame.h"
#include "dk2/MyDxInputState.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/replace_mouse_dinput_to_user32.h"
#include "patches/micro_patches.h"
#include "patches/use_wheel_to_zoom.h"
#include <windowsx.h>

int32_t dk2::MyGame::isOsCompatible() {
    if(add_win10_support::enabled) {
        return !dk2::isOsVersionGE(11, 0, 0);
    }
    return !isOsVersionGE(6, 0, 0);
}

void dk2::resolveDk2HomeDir() {
    if(use_cwd_as_dk2_home_dir::enabled) {
        char tmp[MAX_PATH];
        DWORD len = GetCurrentDirectoryA(MAX_PATH, tmp);
        strcpy(tmp + len, "\\");
        printf("replace exe dir path1: %s -> %s\n", dk2::dk2HomeDir, tmp);
        strcpy(dk2::dk2HomeDir, tmp);
        return;
    }
    const char *CommandLineA = GetCommandLineA();
    _strncpy(pathBuf, CommandLineA, 259u);
    char firstChar = pathBuf[0];
    pathBuf[259] = 0;
    char sepChar = ' ';
    if ( pathBuf[0] == '"' ) {
        signed int idx = 0;
        sepChar = '"';
        unsigned int len = strlen(pathBuf) + 1;
        if ( (int)(len - 1) > 0 ) {
            do {
                pathBuf[idx] = pathBuf[idx + 1];
                ++idx;
            } while ( idx < (int)(len - 1) );
            firstChar = pathBuf[0];
        }
    }
    char *pos = pathBuf;
    if ( firstChar ) {
        char curChar = firstChar;
        do
        {
            if ( curChar == sepChar )
                break;
            curChar = *++pos;
        }
        while ( curChar );
    }
    *pos = 0;
    char *sep1Pos = strrchr(pathBuf, '/');
    char *sep2Pos = strrchr(pathBuf, '\\');
    char **pSepPos = &sep2Pos;
    if ( sep2Pos <= sep1Pos ) pSepPos = &sep1Pos;
    char *sepPos = *pSepPos;
    if ( sepPos ) {
        sepPos[1] = 0;
        setExeDirPath(pathBuf);
    }
}

LRESULT dk2::CWindowTest_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    // patch::BEFORE_WINDOW_PROC
    if(hide_mouse_cursor_in_window::window_proc(hWnd, Msg, wParam, lParam)) return TRUE;
    replace_mouse_dinput_to_user32::emulate_dinput_from_user32(hWnd, Msg, wParam, lParam);
    fix_mouse_pos_on_resized_window::window_proc(hWnd, Msg, wParam, lParam);
    use_wheel_to_zoom::window_proc(hWnd, Msg, wParam, lParam);
    fix_keyboard_state_on_alt_tab::window_proc(hWnd, Msg, wParam, lParam);
    bring_to_foreground::window_proc(hWnd, Msg, wParam, lParam);
    fix_close_window::window_proc(hWnd, Msg, wParam, lParam);
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
            Pos2i pos;
            pos.x = LOWORD(lParam);
            pos.y = HIWORD(lParam);
            MyInputManagerCb_static_setMousePos(&pos);
            break;
        }
    }
    if ( !getCustomDefWindowProcA() )
        return DefWindowProcA(hWnd, Msg, wParam, lParam);
    typedef LRESULT (__stdcall *CustomDefWindowProcA_t)(HWND, UINT, WPARAM, LPARAM);
    auto CustomDefWindowProcA = (CustomDefWindowProcA_t) getCustomDefWindowProcA();
    return CustomDefWindowProcA(hWnd, Msg, wParam, lParam);
}
