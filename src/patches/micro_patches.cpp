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
#include "logging.h"
#include <windowsx.h>


bool patch::modern_windows_support::enabled = true;
bool patch::use_cwd_as_dk2_home_dir::enabled = true;
bool patch::notify_another_instance_is_running::enabled = true;
bool patch::control_windowed_mode::enabled = false;
bool patch::force_32bit_everything::enabled = true;
bool patch::disable_bonus_damage::enabled = false;
bool patch::backstab_fix::enabled = true;
bool patch::workshop_manufacture_build_time_fix::enabled = true;
bool patch::response_to_threat_fix::enabled = true;
bool patch::use_wasd_by_default_patch::enabled = true;
bool patch::print_game_start_errors::enabled = true;
bool patch::creatures_setup_lair_fix::enabled = true;
bool patch::wooden_bridge_burn_fix::enabled = true;
bool patch::max_host_port_number_fix::enabled = true;
bool patch::increase_zoom_level::enabled = true;
bool patch::fix_chat_buffer_invalid_memory_access::enabled = true;
bool patch::hero_party_spawn_limit_fix::enabled = true;
bool patch::drop_thing_from_hand_fix::enabled = true;  // incompatible with 1.7
bool patch::sleeping_possession_fix::enabled = true;

bool patch::override_max_room_count::enabled = true;
uint8_t patch::override_max_room_count::limit = 255;  // default is 96  incompatible with 1.7

void patch::use_wasd_by_default_patch::useAlternativeName(LPCSTR &lpValueName) {
    if(!use_wasd_by_default_patch::enabled) return;
    if(lpValueName && strncmp(lpValueName, "Key Table", 12) == 0) {
        lpValueName = "Key Table Flame";
    }
}

void patch::fix_keyboard_state_on_alt_tab::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                // clear buttons state
                dk2::MyDxInputState *inputState = dk2::MyInputManagerCb_instance.pdxInputState;
                if(inputState != nullptr) {
                    memset(inputState->keyboardState, 0, 256);
                }
            }
            break;
    }
}

void patch::bring_to_foreground::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
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

void patch::fix_close_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_CLOSE: {
            dk2::CDefaultPlayerInterface *playetIf = &dk2::CDefaultPlayerInterface_instance;
            if (playetIf->profiler != nullptr) {  // game is running
                dk2::GameAction action;
                ZeroMemory(&action, sizeof(action));
                action.actionKind = dk2::GA_ExitToWindows;
                action.playerTagId = playetIf->playerTagId;
                playetIf->pushAction(&action);
            } else {
                dk2::setAppExitStatus(true);
            }
            break;
        }
    }
}

namespace {
    bool appIsActive = false;
}
bool patch::hide_mouse_cursor_in_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_SETCURSOR: {
            if(appIsActive) {
                if (LOWORD(lParam) == HTCLIENT) {
                    SetCursor(NULL);
                    return true;
                }
            }
            break;
        }
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                SetCursor(NULL);
                appIsActive = true;
            } else {  // deactivated
                appIsActive = false;
            }
            break;
    }
    return false;
}

namespace {
    POINT window_pos = {50, 50};
    POINT window_size = {0, 0};
    bool ignore_size = true;
}
void patch::remember_window_location_and_size::setInitialSize(int x, int y) {
    window_size = {x, y};
}

bool patch::remember_window_location_and_size::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_DESTROY: {
            ignore_size = true;
            break;
        }
        case WM_MOVE: {
            RECT winRect;
            GetWindowRect(hWnd, &winRect);
            window_pos = {winRect.left, winRect.top};

            break;
        }
        case WM_SIZE: {
            if(!ignore_size) {
                RECT winRect;
                GetWindowRect(hWnd, &winRect);
                window_size = {winRect.right - winRect.left, winRect.bottom - winRect.top};
            }
            break;
        }
    }
    return false;
}
void patch::remember_window_location_and_size::patchWinLoc(int &xPos, int &yPos) {
    xPos = window_pos.x;
    yPos = window_pos.y;
}
void patch::remember_window_location_and_size::resizeWindow(HWND hWnd) {
    if(window_size.x != 0 && window_size.y != 0) {
        SetWindowPos(hWnd, NULL, 0, 0, window_size.x, window_size.y, SWP_NOMOVE | SWP_NOZORDER);
    }
    ignore_size = false;
}

bool patch::skippable_title_screen::enabled = true;
uint32_t patch::skippable_title_screen::waiting_time = 600;  // in milliseconds. by default 10 seconds
bool patch::skippable_title_screen::skipKeyPressed() {
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
void patch::limit_fps::call() {
    DWORD time = GetTickCount();
    int mspf = 1000 / DK2_fps_limit; // 16
    DWORD loopTime = time - lastTime;
    if (loopTime < mspf) {
        SleepEx(mspf - loopTime, FALSE);
    }
    lastTime = time;
}

bool patch::multi_interface_fix::enabled = false;
DWORD patch::multi_interface_fix::getLocalIp(struct hostent *hostent) {
    DWORD ipv4 = 0;
    patch::log::dbg("resolved %s", hostent->h_name);
    for(int i = 0; ; ++i) {
        in_addr *addr = (in_addr *) hostent->h_addr_list[i];
        if(addr == NULL) break;
        patch::log::dbg(" - %s", inet_ntoa(*addr));
        ipv4 = addr->S_un.S_addr;  // use last ip
    }
    return ipv4;
}

