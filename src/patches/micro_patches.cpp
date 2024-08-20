//
// Created by DiaLight on 20.07.2024.
//

#include "micro_patches.h"
#include "dk2/utils/Pos2i.h"
#include "dk2/utils/AABB.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/MyDxInputState.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include <windowsx.h>


bool add_win10_support::enabled = true;
bool use_cwd_as_dk2_home_dir::enabled = true;
bool notify_another_instance_is_running::enabled = true;
bool control_windowed_mode::enabled = true;
bool force_32bit_everything::enabled = true;
bool disable_bonus_damage::enabled = false;
bool backstab_fix::enabled = true;
bool workshop_manufacture_build_time_fix::enabled = true;
bool response_to_threat_fix::enabled = true;
bool use_wasd_by_default_patch::enabled = true;

void use_wasd_by_default_patch::useAlternativeName(LPCSTR &lpValueName) {
    if(!use_wasd_by_default_patch::enabled) return;
    if(lpValueName && strncmp(lpValueName, "Key Table", 12) == 0) {
        lpValueName = "Key Table Flame";
    }
}

void fix_keyboard_state_on_alt_tab::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                // clear buttons state
                memset(dk2::MyInputManagerCb_instance.pdxInputState->keyboardState, 0, 256);
            }
            break;
    }
}

void bring_to_foreground::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_CREATE: {
            SetForegroundWindow(hWnd);
            break;
        }
    }
}

namespace dk2 {
    enum GameActionKind : DWORD {
        GA_ExitToWindows = 0x7D
    };
}

void fix_close_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_CLOSE: {
            dk2::CDefaultPlayerInterface *playetIf = &dk2::CDefaultPlayerInterface_instance;
            if (playetIf->profiler != nullptr) {  // game is running
                dk2::GameAction action;
                ZeroMemory(&action, sizeof(action));
                action.actionKind = dk2::GA_ExitToWindows;
                action._cpyFrF8 = playetIf->_cpyToF10;
                playetIf->pushAction(&action);
            } else {
                dk2::setAppExitStatus(true);
            }
            break;
        }
    }
}

bool hide_mouse_cursor_in_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_SETCURSOR: {
            if (LOWORD(lParam) == HTCLIENT) {
                SetCursor(NULL);
                return true;
            }
        }
    }
    return false;
}

bool skippable_title_screen::enabled = true;
uint32_t skippable_title_screen::waiting_time = 600;  // in milliseconds. by default 10 seconds
bool skippable_title_screen::skipKeyPressed() {
    if(GetAsyncKeyState(VK_SPACE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_ESCAPE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_LBUTTON) & 0x8000) return true;
    if(GetAsyncKeyState(VK_RETURN) & 0x8000) return true;
    SleepEx(50, TRUE);
    return false;
}


namespace {

#define DK2_fps_limit 60
    DWORD lastTime = 0;

}
void limit_fps::call() {
    DWORD time = GetTickCount();
    int mspf = 1000 / DK2_fps_limit;
    int freeTime = mspf - (time - lastTime);
    if (freeTime > 0) {
        SleepEx(freeTime, FALSE);
    }
    lastTime = time;
}
