//
// Created by DiaLight on 20.07.2024.
//

#include "dev_mouse_dinput_to_user32.h"
#include "game_version.h"
#include "write_protect.h"
#include <vector>
#include <windowsx.h>
#include <ntstatus.h>

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

bool dev_mouse_dinput_to_user32::enabled = true;

namespace dk2 {
#pragma pack(push, 1)
    struct DxAction {

/*  0*/ void *vftable;
/*  4*/ int timestamp;
/*  8*/ int isNotHandled;

/*---*/ DxAction() = delete;
/*---*/ ~DxAction() = delete;
/*---*/ // DxAction  -------------------------------------  /* auto */

    };
    static_assert(sizeof(DxAction) == 0xC);
    struct Pos2i {

/*  0*/ int x;
/*  4*/ int y;

    };
    struct MouseRgbDxAction : DxAction {

/*  C*/ uint8_t gap_C[4];
/* 10*/ uint32_t KeyCode_F0toF3;
/* 14*/ Pos2i pos;
/* 1C*/ int data;
/* 20*/ int btnPressFlags;

/*---*/ MouseRgbDxAction() = delete;
/*---*/ ~MouseRgbDxAction() = delete;
/*---*/ // super DxAction  -------------------------------  /* auto */
/*  0*/ // virtual int v_applyToState(MyDxInputState *);  // = 005DD8C0  /* auto */
/*---*/ // MouseRgbDxAction  -----------------------------  /* auto */

    };
    static_assert(sizeof(MouseRgbDxAction) == 0x24);
 struct MouseXyzDxAction : DxAction {
/*00672900*/ __declspec( dllimport ) static void *vftable[];  /* auto */
/*---*/ inline void *getVtbl() const { return *(void **) this; }  /* auto */

/*  C*/ int actedAxe;
/* 10*/ int value;

/*---*/ MouseXyzDxAction() = delete;
/*---*/ ~MouseXyzDxAction() = delete;


};
static_assert(sizeof(MouseXyzDxAction) == 0x14);
    struct AABB {

/*  0*/ int minX;
/*  4*/ int minY;
/*  8*/ int maxX;
/*  C*/ int maxY;

/*00404DB0*/ AABB *constructor();
/*00404DC0*/ AABB *constructor_0(int, int, int, int);       /* auto */
/*0044BD30*/ BOOL sub_44BD30(AABB *);
/*0052D3A0*/ BOOL contains(AABB *);
/*00556590*/ AABB *appendPoint(AABB *, tagPOINT *);
/*005B6FD0*/ AABB *intersection(AABB *, AABB *);
/*005B7050*/ BOOL isIntersects(AABB *);
/*005B7090*/ AABB *getOuter(AABB *, AABB *);
/*005B7100*/ int sub_5B7100();
/*005DC2D0*/ int move(int, int);

    };
    static_assert(sizeof(AABB) == 0x10);
    struct MySharedObj {  // ---------------------------------  /* auto */
// -------------------------------------------------------  /* auto */
/*  0*/ uint8_t *vftable;  // ------------------------------------  /* auto */
/*  4*/ int refs;  // ------------------------------------  /* auto */
// -------------------------------------------------------  /* auto */
/*---*/ MySharedObj() = delete;  // ----------------------  /* auto */
/*---*/ ~MySharedObj() = delete;  // ---------------------  /* auto */
/*---*/ // MySharedObj  ----------------------------------  /* auto */
///*  0*/ virtual int v_release();  // = 0062FC10  ---------  /* auto */
///*  4*/ virtual int v_addRef();  // = 0062FC00  ----------  /* auto */
///*  8*/ virtual MySharedObj *v_scalar_destructor(char);  // = 005BB710  /* auto */
// -------------------------------------------------------  /* auto */
/*005BB710*/ MySharedObj *deleting_destructor(char);  // -  /* auto */
/*005DCA30*/ MySharedObj *constructor();  // -------------  /* auto */
/*0062FC00*/ int addRef();  // ---------------------------  /* auto */
/*0062FC10*/ int release();  // --------------------------  /* auto */
// -------------------------------------------------------  /* auto */
    };  // ---------------------------------------------------  /* auto */
    static_assert(sizeof(MySharedObj) == 0x8);  // -----------  /* auto */
    struct MyComEx : MySharedObj {  // -----------------------  /* auto */
// -------------------------------------------------------  /* auto */
/*  8*/ MyComEx *f4_child;  // ---------------------------  /* auto */
// -------------------------------------------------------  /* auto */
/*---*/ MyComEx() = delete;  // --------------------------  /* auto */
/*---*/ ~MyComEx() = delete;  // -------------------------  /* auto */
/*---*/ // super MySharedObj  ----------------------------  /* auto */
/*  0*/ // virtual int v_release();  // = 0062FC10  ------  /* auto */
/*  4*/ // virtual int v_addRef();  // = 0062FC00  -------  /* auto */
/*  8*/ // virtual MySharedObj *v_scalar_destructor(char);  // = 005BB790  /* auto */
/*---*/ // MyComEx  --------------------------------------  /* auto */
///*  C*/ virtual void v_fun1(int);  // = 005671E0  --------  /* auto */
///* 10*/ virtual int v_fun2_wndmsg(DxAction *);  // = 005BB760  /* auto */
///* 14*/ virtual int v_fun3_mouse(DxAction *);  // = 005BB660  /* auto */
///* 18*/ virtual int v_fun4_keyboard(DxAction *);  // = 005BB730  /* auto */
// -------------------------------------------------------  /* auto */
/*005BB660*/ DxAction *fun3_mouse(DxAction *);  // -------  /* auto */
/*005BB730*/ DxAction *fun4(DxAction *);  // -------------  /* auto */
/*005BB760*/ int fun2_wndmsg(DxAction *);  // ------------  /* auto */
/*005BB790*/ MyComEx *deleting_destructor(char);  // -----  /* auto */
/*005BB7B0*/ int destructor();  // -----------------------  /* auto */
/*005DA2D0*/ int setChild(MyComEx *);  // ----------------  /* auto */
// -------------------------------------------------------  /* auto */
    };  // ---------------------------------------------------  /* auto */
    static_assert(sizeof(MyComEx) == 0xC);  // ---------------  /* auto */
    struct ControlKeysUpdater : MyComEx {  // ----------------  /* auto */
// -------------------------------------------------------  /* auto */
// -------------------------------------------------------  /* auto */
/*---*/ ControlKeysUpdater() = delete;  // ---------------  /* auto */
/*---*/ ~ControlKeysUpdater() = delete;  // --------------  /* auto */
/*---*/ // super MySharedObj  ----------------------------  /* auto */
/*  0*/ // virtual int v_release();  // = 0062FC10  ------  /* auto */
/*  4*/ // virtual int v_addRef();  // = 0062FC00  -------  /* auto */
/*  8*/ // virtual MySharedObj *v_scalar_destructor(char);  // = 005DCF40  /* auto */
/*---*/ // super MyComEx  --------------------------------  /* auto */
/*  C*/ // virtual void v_fun1(int);  // = 005671E0  -----  /* auto */
/* 10*/ // virtual int v_fun2_wndmsg(DxAction *);  // = 005BB760  /* auto */
/* 14*/ // virtual int v_fun3_mouse(DxAction *);  // = 005BB660  /* auto */
/* 18*/ // virtual int v_fun4_keyboard(DxAction *);  // = 005DD010  /* auto */
/*---*/ // ControlKeysUpdater  ---------------------------  /* auto */
// -------------------------------------------------------  /* auto */
    };  // ---------------------------------------------------  /* auto */

    ControlKeysUpdater **MyInputManagerCb_instance_f5C_controlKeys = (ControlKeysUpdater **) (0x0079CF90 + 0x60);
    uint8_t **MyInputManagerCb_instance_f60_mouse = (uint8_t **) (0x0079CF90 + 0x64);
    void **g_pWorld = (void **) 0x006E5050;
    typedef void (__fastcall *MyMouse_updatePos_t)(void *);
    MyMouse_updatePos_t MyMouse_updatePos = (MyMouse_updatePos_t) 0x005DD630;

#pragma pack(pop)
}
namespace {
    std::vector<dk2::MouseRgbDxAction *> rgbActionsInProgress;
    std::vector<dk2::MouseXyzDxAction *> xyzActionsInProgress;
}

// x=0 y=4 z=8
void move_mouse(DWORD offs, DWORD value) {
    auto *updater = *dk2::MyInputManagerCb_instance_f5C_controlKeys;

//    MouseXyzDxAction *action = this->listXYZ.getOrCreateUnhandled();
    auto *action = (dk2::MouseXyzDxAction *) new char[sizeof(dk2::MouseXyzDxAction)];
    *(void **) action = (void *) 0x00672900;
    xyzActionsInProgress.push_back(action);

    action->value = value;  // relative or absolute motion
    action->actedAxe = offs;
    action->timestamp = GetTickCount();
    action->isNotHandled = 1;
    typedef void (__fastcall *MyComEx_fun3_t)(void *this_, void *edx, void *a2);
    (*(MyComEx_fun3_t *) (updater->vftable + 0x14))(updater, NULL, action);
}

void click_mouse(DWORD dik_scancode, DWORD flags) {
    auto *updater = *dk2::MyInputManagerCb_instance_f5C_controlKeys;
    // do not try to call constructor/destructor
    auto *action = (dk2::MouseRgbDxAction *) new char[sizeof(dk2::MouseRgbDxAction)];
    *(void **) action = (void *) 0x006728F8;
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
    typedef void (__fastcall *MyComEx_fun3_t)(void *this_, void *edx, void *a2);
    (*(MyComEx_fun3_t *) (updater->vftable + 0x18))(updater, NULL, action);
}

namespace {
    DWORD controlFlags = 0;
    dk2::Pos2i clientSize;
    POINT lastPos = {0, 0};

    RECT safeArea;
    POINT clientResetPos;
}

void handle_fpv_mouse_move(HWND hWnd, POINT pos) {
    // update safe area
    RECT clientRect;
    GetClientRect(hWnd, &clientRect);

    safeArea = clientRect;
    safeArea.left += (clientRect.right - clientRect.left) / 3;
    safeArea.top += (clientRect.bottom - clientRect.top) / 3;
    safeArea.right -= (clientRect.right - clientRect.left) / 3;
    safeArea.bottom -= (clientRect.bottom - clientRect.top) / 3;

    // update reset pos
    clientResetPos.x = (clientRect.left + clientRect.right) / 2;
    clientResetPos.y = (clientRect.top + clientRect.bottom) / 2;

//    float sensitivity = dk2::MyResources_instance.playerCfg.mouseSensitivity / 10.0;
    float sensitivity = 1;
    if(pos.x != lastPos.x) {
// 28 float f24_flX_delta;  // -------------------------  /* auto */
        *((float *) (*dk2::MyInputManagerCb_instance_f60_mouse + 0x28)) = (float) (pos.x - lastPos.x) * sensitivity;
        lastPos.x = pos.x;
    }
    if(pos.y != lastPos.y) {
// 2C float f28_flY_delta;  // -------------------------  /* auto */
        *((float *) (*dk2::MyInputManagerCb_instance_f60_mouse + 0x2C)) = (float) (pos.y - lastPos.y) * sensitivity;
        lastPos.y = pos.y;
    }

    if(!PtInRect(&safeArea, pos)) {
        lastPos = clientResetPos;
        POINT screenResetPos = clientResetPos;
        ClientToScreen(hWnd, &screenResetPos);
        SetCursorPos(screenResetPos.x, screenResetPos.y);
//        printf("move to center cur=%d,%d client=%d,%d,%d,%d  reset=%d,%d safe=%d,%d,%d,%d  screen=%d,%d\n",
//               pos.x, pos.y,
//               clientRect.left, clientRect.top,
//               clientRect.right, clientRect.bottom,
//               clientResetPos.x, clientResetPos.y,
//               safeArea.left, safeArea.top,
//               safeArea.right, safeArea.bottom,
//               screenResetPos.x, screenResetPos.y
//        );
    }
}

void dev_mouse_dinput_to_user32::handle_mouse_move(HWND hWnd, POINT pos) {
    // handle gui mouse
// 34 AABB f30_aabb;  // -------------------------------  /* auto */
    dk2::AABB renderRect = *((dk2::AABB *) (*dk2::MyInputManagerCb_instance_f60_mouse + 0x34));
    dk2::Pos2i renderSize = {renderRect.maxX - renderRect.minX, renderRect.maxY - renderRect.minY};
    POINT renderPos = {
            (int) ((float) pos.x * (float) renderSize.x / (float) clientSize.x),
            (int) ((float) pos.y * (float) renderSize.y / (float) clientSize.y)
    };

/* 20*/ float f1C_flX;  // -------------------------------  /* auto */
    *((float *) (*dk2::MyInputManagerCb_instance_f60_mouse + 0x20)) = renderPos.x;
/* 24*/ float f20_flY;  // -------------------------------  /* auto */
    *((float *) (*dk2::MyInputManagerCb_instance_f60_mouse + 0x24)) = renderPos.y;
    dk2::MyMouse_updatePos(*dk2::MyInputManagerCb_instance_f60_mouse);

    // handle first person view mouse
    if(*dk2::g_pWorld != NULL) {
//        if(dk2::CPlayer *pl = (dk2::CPlayer *) dk2::sceneObjects[dk2::g_pWorld->v_getMEPlayerTagId()]) {
//            if(pl->creaturePossessed != 0 && !dk2::CDefaultPlayerInterface_instance.inMenu) {
//                // keep mouse in the center of window
//                handle_fpv_mouse_move(hWnd, pos);
//            }
//        }
    }
}
void dev_mouse_dinput_to_user32::emulate_dinput_from_user32(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if(!enabled) return;
    switch (Msg) {
        case WM_SIZE: {
            clientSize = {LOWORD(lParam), HIWORD(lParam)};
            break;
        }
        case WM_MOUSEMOVE: {
            POINT mousePos = {GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
            handle_mouse_move(hWnd, mousePos);
            break;
        }
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
void dev_mouse_dinput_to_user32::release_handled_dinput_actions() {
    {
        auto it = std::remove_if(rgbActionsInProgress.begin(), rgbActionsInProgress.end(), [](dk2::MouseRgbDxAction *action) {
            if (action->isNotHandled) return false;
            delete[] (char *) action;
            return true;
        });
        rgbActionsInProgress.erase(it, rgbActionsInProgress.end());
    }

    auto it = std::remove_if(xyzActionsInProgress.begin(), xyzActionsInProgress.end(), [](dk2::MouseXyzDxAction *action) {
        if (action->isNotHandled) return false;
        delete[] (char *) action;
        return true;
    });
    xyzActionsInProgress.erase(it, xyzActionsInProgress.end());
}

typedef LRESULT (__stdcall *CWindowTest_proc_t)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
CWindowTest_proc_t CWindowTest_proc = (CWindowTest_proc_t) 0x00556650;
LRESULT __stdcall proxy_CWindowTest_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    dev_mouse_dinput_to_user32::emulate_dinput_from_user32(hWnd, Msg, wParam, lParam);
    dev_mouse_dinput_to_user32::release_handled_dinput_actions();
    return CWindowTest_proc(hWnd, Msg, wParam, lParam);
}
int *__fastcall replace_MyDxInputManagerCb_initMouse(void *this_, void *edx, int *pstatus) {
    *pstatus = STATUS_SUCCESS;
    return pstatus;
}


uintptr_t addr(uint32_t va);
void dev_mouse_dinput_to_user32::initialize() {

    {
        auto xref = (dk2_version == 170 ? 0x005BB1F8 : 0);
        auto pos = addr(xref + 1);
        write_protect prot((void *) pos, sizeof(uintptr_t));
        *(DWORD *) pos = (uintptr_t) replace_MyDxInputManagerCb_initMouse - (pos + 4);
    }
    {
        auto xref = (dk2_version == 170 ? 0x00555D34 : 0);
        write_protect prot((void *) xref, sizeof(uintptr_t));
        *(DWORD *) xref = (uintptr_t) proxy_CWindowTest_proc;
    }
}

