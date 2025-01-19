//
// Created by DiaLight on 09.07.2024.
//
#include <ntstatus.h>

#define UMDF_USING_NTSTATUS

#include "dk2/MyDxMouse.h"
#include "dk2/MyDxInputManagerCb.h"
#include "dk2/MouseXyzDxAction.h"
#include "dk2/MouseRgbDxAction.h"
#include "dk2/ControlKeysUpdater.h"
#include "dk2/MyDxKeyboard.h"
#include "dk2_functions.h"
#include "patches/replace_mouse_dinput_to_user32.h"
#include "patches/use_wheel_to_zoom.h"
#include "dk2_memory.h"

int *dk2::MyDxInputManagerCb::initMouse(int *pstatus) {
    if (this->f58_pdxmouse) {
        *pstatus = 0xCFFE0102;
        return pstatus;
    }
    if (patch::replace_mouse_dinput_to_user32::enabled) {
        *pstatus = STATUS_SUCCESS;
        return pstatus;
    }
    int status;
    MyDxMouse_create(&status, &this->f58_pdxmouse);
    if (FAILED(status)) {
        *pstatus = status;
        return pstatus;
    }
    this->fC_async.setObjAndSignal(&status, (uint32_t *) this->f58_pdxmouse);
    if (FAILED(status)) {
        *pstatus = status;
        return pstatus;
    }
    this->f58_pdxmouse->setControlKeysUpdater(this->f5C_controlKeys);
    this->f58_pdxmouse->dx_device.updateCoopLevel_acquire(&status);
    *pstatus = STATUS_SUCCESS;
    return pstatus;
}

int *__cdecl dk2::MyDxMouse_create(int *pstatus, MyDxMouse **pObj) {
    if (pObj == nullptr) {
        *pstatus = 0x80004003;
        return pstatus;
    }
    MyDxMouse *obj = (MyDxMouse *) dk2::operator_new(sizeof(MyDxMouse));
    if (obj == nullptr) {
        *pstatus = 0xCFFE0100;
        return pstatus;
    }
    obj->constructor();
    HRESULT result;
    obj->initDevice_0(&result);
    if (FAILED(result)) {
        obj->v_scalar_destructor(1);
        *pstatus = result;
        return pstatus;
    }
    *pObj = obj;
    *pstatus = STATUS_SUCCESS;
    return pstatus;
}

void dk2::MyDxMouse::handleData(int count) {
    if (!count) return;
    for (int i = 0; i < count; ++i) {
        DIDEVICEOBJECTDATA &pdevObj = this->f2C_pdevObjArr[i];
        switch (pdevObj.dwOfs) {
            case 0:                                 // x y z
            case 4:
            case 8: {
                MouseXyzDxAction *xyz = this->listXYZ.getOrCreateUnhandled();
                int f8_dwTimeStamp = pdevObj.dwTimeStamp;
                int f0_dwOfs = pdevObj.dwOfs;
                xyz->value = pdevObj.dwData;  // relative or absolute motion
                xyz->actedAxe = f0_dwOfs;
                xyz->timestamp = f8_dwTimeStamp;
                xyz->isNotHandled = 1;
                this->f8_pcontrolkeys->v_fun3_mouse(xyz);
            } break;
            case 0xC:                               // rgbButtons
            case 0xD:
            case 0xE:
            case 0xF: {
                MouseRgbDxAction *action = this->listRGB.getOrCreateUnhandled();
                switch (pdevObj.dwOfs) {
                    case 0xC:
                        count = 0xF0;                     // left mouse
                        break;
                    case 0xD:
                        count = 0xF1;                     // right mouse
                        break;
                    case 0xE:
                        count = 0xF2;                     // middle mouse
                        break;
                    case 0xF:
                        count = 0xF3;                     // unk mouse
                        break;
                    default:
                        break;
                }
                char f4_dwData = pdevObj.dwData;
                int dwTimeStamp = pdevObj.dwTimeStamp;
                int isPressed = ((unsigned int) pdevObj.dwData >> 4) & 8;
                action->KeyCode_F0toF3 = count;
                action->btnPressFlags = isPressed;
                action->pos.x = 0;
                action->pos.y = 0;
                action->data = f4_dwData;
                action->timestamp = dwTimeStamp;
                action->isNotHandled = 1;
                this->f8_pcontrolkeys->v_fun4_keyboard(action);
            } break;
            default:
                break;
        }
        // hook::DIRECT_INPUT_MOUSE_DATA
        patch::use_wheel_to_zoom::dinput_proc(&pdevObj);
    }
}

uint32_t *dk2::MyDxInputManagerCb::onWindowActivated(uint32_t *psatatus, int isActivated) {
    this->f54_pdxKeyboard->dx_device.updateWindowActive(isActivated);
    if (!patch::replace_mouse_dinput_to_user32::enabled) {
        this->f58_pdxmouse->dx_device.updateWindowActive(isActivated);
    }
    this->updateCoopLevelAndSignal(psatatus);
    return psatatus;
}
