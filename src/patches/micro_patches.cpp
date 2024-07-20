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


namespace {
    dk2::Pos2i clientSize;
}
void fix_mouse_pos_on_resized_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch (Msg) {
        case WM_SIZE: {
            clientSize = {LOWORD(lParam), HIWORD(lParam)};
            break;
        }
        case WM_MOUSEMOVE: {
            dk2::Pos2i pos = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            dk2::AABB renderRect = dk2::MyInputManagerCb_instance.f60_mouse->f30_aabb;
            dk2::Pos2i renderSize = {renderRect.maxX - renderRect.minX, renderRect.maxY - renderRect.minY};
            pos.x = (int) ((float) pos.x * (float) renderSize.x / (float) clientSize.x);
            pos.y = (int) ((float) pos.y * (float) renderSize.y / (float) clientSize.y);
            lParam = (pos.x & 0xFFFF) | ((pos.y & 0xFFFF) << 16);
            break;
        }
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

bool skippable_title_screen::enabled = true;
bool skippable_title_screen::skipKeyPressed() {
    if(!skippable_title_screen::enabled) return false;
    if(GetAsyncKeyState(VK_SPACE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_ESCAPE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_LBUTTON) & 0x8000) return true;
    if(GetAsyncKeyState(VK_RETURN) & 0x8000) return true;
    SleepEx(50, TRUE);
    return false;
}

