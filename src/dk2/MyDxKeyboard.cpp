//
// Created by DiaLight on 26.07.2024.
//
#include "dk2/MyDxKeyboard.h"
#include "dk2/MouseRgbDxAction.h"
#include "dk2/ControlKeysUpdater.h"


int dk2::MyDxKeyboard::processKeyboardData(int a2) {
    int result = a2 - 1;
    for (DIDEVICEOBJECTDATA *i = this->f2C_pdevObjArr; a2; --a2) {
        MouseRgbDxAction *action = this->listKb.getOrCreateUnhandled();
        char f4_dwData = i->dwData;
        int f8_dwTimeStamp = i->dwTimeStamp;
        int f0_dwOfs = (unsigned __int8) i->dwOfs;
        action->btnPressFlags = ((unsigned int) i->dwData >> 4) & 8;
        action->pos.x = 0;
        action->KeyCode_F0toF3 = f0_dwOfs;
        action->pos.y = 0;
        action->data = f4_dwData;
        action->timestamp = f8_dwTimeStamp;
        action->isNotHandled = 1;
        this->f8_pcontrolkeys->v_fun4_keyboard((DxAction *) action);
        // hook::DIRECT_INPUT_KEYBOARD_DATA
        ++i;
        result = a2 - 1;
    }
    return result;
}
