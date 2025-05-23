//
// Created by DiaLight on 20.07.2024.
//

#include "replace_mouse_dinput_to_user32.h"
#include "dk2_globals.h"
#include "dk2/MouseRgbDxAction.h"
#include "dk2/ControlKeysUpdater.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/MouseXyzDxAction.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/dk2_memory.h"
#include <vector>
#include <windowsx.h>

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

bool patch::replace_mouse_dinput_to_user32::enabled = true;

namespace {
    std::vector<dk2::MouseRgbDxAction *> rgbActionsInProgress;
    std::vector<dk2::MouseXyzDxAction *> xyzActionsInProgress;
}

// x=0 y=4 z=8
void move_mouse(DWORD offs, DWORD value) {
    auto *updater = dk2::MyInputManagerCb_instance.f5C_controlKeys;

//    MouseXyzDxAction *action = this->listXYZ.getOrCreateUnhandled();
    auto *action = (dk2::MouseXyzDxAction *) dk2::operator_new(sizeof(dk2::MouseXyzDxAction));
    *(void **) action = &dk2::MouseXyzDxAction::vftable;
    xyzActionsInProgress.push_back(action);

    action->value = value;  // relative or absolute motion
    action->actedAxe = offs;
    action->timestamp = GetTickCount();
    action->isNotHandled = 1;
    updater->v_fun3_mouse(action);
}

void click_mouse(DWORD dik_scancode, DWORD flags) {
    auto *updater = dk2::MyInputManagerCb_instance.f5C_controlKeys;
    // do not try to call constructor/destructor
    auto *action = (dk2::MouseRgbDxAction *) dk2::operator_new(sizeof(dk2::MouseRgbDxAction));
    *(void **) action = &dk2::MouseRgbDxAction::vftable;
    rgbActionsInProgress.push_back(action);

//  action.f10_KeyCode_F0toF3 = click_dinput_to_dk2(dinput_dwOffs);
    action->KeyCode_F0toF3 = dik_scancode;
    action->btnPressFlags = flags;
    action->pos.x = 0;
    action->pos.y = 0;
    // action->f1C_data = LOBYTE(DIDEVICEOBJECTDATA.dwData)
    action->data = flags & DK2_IsPressed ? 0x80 : 0x00;
    action->timestamp = GetTickCount();
    action->isNotHandled = 1;
    updater->v_fun4_keyboard(action);
}

namespace {
    DWORD controlFlags = 0;
    dk2::Pos2i clientSize;
    bool appIsActive = false;
    POINT g_savedPos;
    bool g_wasRelative = false;
}

void handle_fpv_mouse_move(HWND hWnd, POINT pos) {
    // update safe area
    RECT clientRect;
    GetClientRect(hWnd, &clientRect);

    RECT safeArea;
    safeArea = clientRect;
    safeArea.left += (clientRect.right - clientRect.left) / 3;
    safeArea.top += (clientRect.bottom - clientRect.top) / 3;
    safeArea.right -= (clientRect.right - clientRect.left) / 3;
    safeArea.bottom -= (clientRect.bottom - clientRect.top) / 3;

    // update reset pos
    POINT clientResetPos;
    clientResetPos.x = (clientRect.left + clientRect.right) / 2;
    clientResetPos.y = (clientRect.top + clientRect.bottom) / 2;
    POINT lastPos = clientResetPos;

    float sensitivity = dk2::MyResources_instance.playerCfg.mouseSensitivity / 10.0;
    if(pos.x != lastPos.x) {
        float delta = (float) (pos.x - lastPos.x) / (float) clientSize.x * 640;
        dk2::MyInputManagerCb_instance.f60_mouse->f24_flX_delta = delta * sensitivity;
        lastPos.x = pos.x;
    }
    if(pos.y != lastPos.y) {
        float delta = (float) (pos.y - lastPos.y) / (float) clientSize.y * 480;
        dk2::MyInputManagerCb_instance.f60_mouse->f28_flY_delta = delta * sensitivity;
        lastPos.y = pos.y;
    }
    POINT screenResetPos = clientResetPos;
    ClientToScreen(hWnd, &screenResetPos);
    SetCursorPos(screenResetPos.x, screenResetPos.y);
}

void patch::replace_mouse_dinput_to_user32::handle_mouse_move(HWND hWnd, POINT pos) {
    bool relativeMode = false;
    // handle first person view mouse
    if(dk2::g_pWorld != NULL) {
        if(dk2::CPlayer *pl = (dk2::CPlayer *) dk2::sceneObjects[dk2::g_pWorld->v_getMEPlayerTagId()]) {
            if (!dk2::CDefaultPlayerInterface_instance.inMenu) {
                if(pl->creaturePossessed != 0 || dk2::CDefaultPlayerInterface_instance.isMouseRotateOrSoomPressed) {
                    relativeMode = true;
                }
            }
        }
    }
    if (relativeMode) {
        if (!g_wasRelative) {
            g_savedPos = pos;

            RECT clientRect;
            GetClientRect(hWnd, &clientRect);
            POINT clientResetPos;
            clientResetPos.x = (clientRect.left + clientRect.right) / 2;
            clientResetPos.y = (clientRect.top + clientRect.bottom) / 2;
            POINT screenResetPos = clientResetPos;
            ClientToScreen(hWnd, &screenResetPos);
            SetCursorPos(screenResetPos.x, screenResetPos.y);
            pos = clientResetPos;
        }
        // keep mouse in the center of window
        handle_fpv_mouse_move(hWnd, pos);
    } else {
        if (g_wasRelative) {
            POINT screenResetPos = g_savedPos;
            ClientToScreen(hWnd, &screenResetPos);
            SetCursorPos(screenResetPos.x, screenResetPos.y);
            pos = g_savedPos;
        }
        // handle gui mouse
        dk2::AABB renderRect = dk2::MyInputManagerCb_instance.f60_mouse->f30_aabb;
        dk2::Pos2i renderSize = {renderRect.maxX - renderRect.minX, renderRect.maxY - renderRect.minY};
        POINT renderPos = {
            (int) ((float) pos.x * (float) renderSize.x / (float) clientSize.x),
            (int) ((float) pos.y * (float) renderSize.y / (float) clientSize.y)
        };
        dk2::MyInputManagerCb_instance.f60_mouse->f1C_flX = renderPos.x;
        dk2::MyInputManagerCb_instance.f60_mouse->f20_flY = renderPos.y;
        dk2::MyInputManagerCb_instance.f60_mouse->updatePos();
    }
    g_wasRelative = relativeMode;
}
void patch::replace_mouse_dinput_to_user32::emulate_dinput_from_user32(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if(!enabled) return;
    switch (Msg) {
        case WM_SIZE: {
            RECT clientRect;
            GetClientRect(hWnd, &clientRect);
            clientSize = {clientRect.right - clientRect.left, clientRect.bottom - clientRect.top};
//            clientSize = {LOWORD(lParam), HIWORD(lParam)};
            break;
        }
        case WM_MOUSEMOVE: {
            if(appIsActive) {
                POINT mousePos;
                GetCursorPos(&mousePos);
                ScreenToClient(hWnd, &mousePos);
//                POINT mousePos = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
                handle_mouse_move(hWnd, mousePos);
            }
            break;
        }
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                appIsActive = true;
            } else {  // deactivated
                appIsActive = false;
            }
            break;
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
    }
}
void patch::replace_mouse_dinput_to_user32::release_handled_dinput_actions() {
    {
        auto it = std::remove_if(rgbActionsInProgress.begin(), rgbActionsInProgress.end(), [](dk2::MouseRgbDxAction *action) {
            if (action->isNotHandled) return false;
            dk2::operator_delete(action);
            return true;
        });
        rgbActionsInProgress.erase(it, rgbActionsInProgress.end());
    }

    auto it = std::remove_if(xyzActionsInProgress.begin(), xyzActionsInProgress.end(), [](dk2::MouseXyzDxAction *action) {
        if (action->isNotHandled) return false;
        dk2::operator_delete(action);
        return true;
    });
    xyzActionsInProgress.erase(it, xyzActionsInProgress.end());
}

