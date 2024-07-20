//
// Created by DiaLight on 20.07.2024.
//

#include "replace_mouse_dinput_to_user32.h"
#include "dk2_globals.h"
#include "dk2/MouseRgbDxAction.h"
#include "dk2/ControlKeysUpdater.h"
#include <vector>

// click flags
#define DK2_Shift 0x01
#define DK2_Ctrl 0x02
#define DK2_Alt 0x04
#define DK2_IsPressed 0x08
#define DK2_IsDblClick 0x10

// dk2 extends dinput scancodes for keyboard to add mouse keys in keyboard state array
#define DIK_DK2_LEFTMOUSE 0xF0
#define DIK_DK2_RIGHTMOUSE 0xF1
#define DIK_DK2_MIDDLEMOUSE 0xF2
#define DIK_DK2_UNKMOUSE 0xF3

bool replace_mouse_dinput_to_user32::enabled = true;

namespace {
    std::vector<dk2::MouseRgbDxAction *> actionsInProgress;
}

void click_mouse(DWORD dik_scancode, DWORD flags) {
    auto *updater = dk2::MyInputManagerCb_instance.f5C_controlKeys;
    // do not try to call constructor/destructor
    auto *action = (dk2::MouseRgbDxAction *) new char[sizeof(dk2::MouseRgbDxAction)];
    *(void **) action = &dk2::MouseRgbDxAction_vftable;
//  action.f10_KeyCode_F0toF3 = click_dinput_to_dk2(dinput_dwOffs);
    action->KeyCode_F0toF3 = dik_scancode;
    action->btnPressFlags = flags;
    action->pos.x = 0;
    action->pos.y = 0;
    // action->f1C_data = LOBYTE(DIDEVICEOBJECTDATA.dwData)
    action->data = flags & DK2_IsPressed ? 0x80 : 0x00;
    action->timestamp = GetTickCount();
    action->isNotHandled = 1;
    actionsInProgress.push_back(action);
    updater->v_fun4(action);
}

namespace {
    DWORD controlFlags = 0;
    dk2::Pos2i clientSize;
}

void replace_mouse_dinput_to_user32::emulate_dinput_from_user32(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch (Msg) {
        case WM_LBUTTONDOWN:
            click_mouse(DIK_DK2_LEFTMOUSE, DK2_IsPressed | controlFlags);
            break;
        case WM_LBUTTONUP:
            click_mouse(DIK_DK2_LEFTMOUSE, 0 | controlFlags);
            break;
        case WM_LBUTTONDBLCLK:
            click_mouse(DIK_DK2_LEFTMOUSE, DK2_IsDblClick | controlFlags);
            break;
        case WM_RBUTTONDOWN:
            click_mouse(DIK_DK2_RIGHTMOUSE, DK2_IsPressed | controlFlags);
            break;
        case WM_RBUTTONUP:
            click_mouse(DIK_DK2_RIGHTMOUSE, 0 | controlFlags);
            break;
        case WM_RBUTTONDBLCLK:
            click_mouse(DIK_DK2_RIGHTMOUSE, DK2_IsDblClick | controlFlags);
            break;
        case WM_MBUTTONDOWN:
            click_mouse(DIK_DK2_MIDDLEMOUSE, DK2_IsPressed | controlFlags);
            break;
        case WM_MBUTTONUP:
            click_mouse(DIK_DK2_MIDDLEMOUSE, 0 | controlFlags);
            break;
        case WM_MBUTTONDBLCLK:
            click_mouse(DIK_DK2_MIDDLEMOUSE, DK2_IsDblClick | controlFlags);
            break;
        case WM_XBUTTONDOWN:
            click_mouse(DIK_DK2_UNKMOUSE, DK2_IsPressed | controlFlags);
            break;
        case WM_XBUTTONUP:
            click_mouse(DIK_DK2_UNKMOUSE, 0 | controlFlags);
            break;
        case WM_XBUTTONDBLCLK:
            click_mouse(DIK_DK2_UNKMOUSE, DK2_IsDblClick | controlFlags);
            break;
        case WM_KEYDOWN: {
            switch (wParam) {
                case VK_SHIFT:
                    controlFlags |= DK2_Shift;
                case VK_CONTROL:
                    controlFlags |= DK2_Ctrl;
                case VK_MENU:
                    controlFlags |= DK2_Alt;
            }
            break;
        }
        case WM_KEYUP: {
            switch (wParam) {
                case VK_SHIFT:
                    controlFlags &= ~DK2_Shift;
                case VK_CONTROL:
                    controlFlags &= ~DK2_Ctrl;
                case VK_MENU:
                    controlFlags &= ~DK2_Alt;
            }
            break;
        }
        case WM_SIZE: {
            clientSize = {LOWORD(lParam), HIWORD(lParam)};
            break;
        }
    }
}
