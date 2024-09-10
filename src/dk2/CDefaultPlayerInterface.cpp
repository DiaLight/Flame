//
// Created by DiaLight on 10.09.2024.
//
#include "dk2/CDefaultPlayerInterface.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"


int dk2::CDefaultPlayerInterface::tickKeyboard2() {
    int v18_try_catch;

    Pos2i *MousePos = MyGame_instance.getMousePos();
    int x = MousePos->x;
    int y = MousePos->y;
    int controlKeyFlags = MyInputManagerCb_static_buildControlFlags();
    int v15_isLControl = isActionKeyPressed(20, controlKeyFlags, 1);  // DIK_LCONTROL
    int v5_isLShift = isActionKeyPressed(21, controlKeyFlags, 1);  // DIK_LSHIFT
    int v13_isLShift = v5_isLShift;
    int ignoreModifiers = 0;
    if ( v15_isLControl || v5_isLShift) ignoreModifiers = 1;
    int dwWidth = MyGame_instance.dwWidth;
    int dwHeight = MyGame_instance.dwHeight;

    if(!control_windowed_mode::disable_move_by_mouse) {
        if ( x < 5 )
            this->pushMoveKeyAction(0, 0);
        if ( x > dwWidth - 5 )
            this->pushMoveKeyAction(1, 0);
        if ( y < 5 )
            this->pushMoveKeyAction(2, 0);
        if ( y > dwHeight - 5 )
            this->pushMoveKeyAction(3, 0);
    }

    if ( !v15_isLControl ) {
        int v8_isLShift = v13_isLShift;
        if ( isActionKeyPressed(18, controlKeyFlags, ignoreModifiers) ) {  // DIK_LEFT
            if (MyResources_instance.playerCfg.isAlternativeScroll) {
                __int16 v7 = this->_cpyToF10;
                GameAction v17_action;
                v17_action.f0 = -64;
                v17_action.f4 = 0.0;
                v17_action.f8 = 0;
                v17_action.actionKind = 8;
                v17_action._cpyFrF8 = v7;
                v18_try_catch = 0;
                this->pushAction(&v17_action);
                v18_try_catch = -1;
            } else {
                this->pushMoveKeyAction(0, v13_isLShift);
            }
        }
        if ( isActionKeyPressed(19, controlKeyFlags, ignoreModifiers) ) {  // DIK_RIGHT
            if ( MyResources_instance.playerCfg.isAlternativeScroll ) {
                __int16 f8__cpyToF10 = this->_cpyToF10;
                GameAction v17_action;
                v17_action.f0 = 64;
                v17_action.f4 = 0.0;
                v17_action.f8 = 0;
                v17_action.actionKind = 8;
                v17_action._cpyFrF8 = f8__cpyToF10;
                v18_try_catch = 1;
                this->pushAction(&v17_action);
                v18_try_catch = -1;
            } else {
                this->pushMoveKeyAction(1, v8_isLShift);
            }
        }
        if ( isActionKeyPressed(16, controlKeyFlags, ignoreModifiers) )// DIK_UP
            this->pushMoveKeyAction(2, v8_isLShift);
        if ( isActionKeyPressed(17, controlKeyFlags, ignoreModifiers) )// DIK_DOWN
            this->pushMoveKeyAction(3, v8_isLShift);
    }
    int result = this->f1094;
    if ( !result && !this->f1098 )
        return 0;
    GameAction v17_action;
    v17_action.f8 = 0;
    v17_action.actionKind = 3;
    v17_action.f0 = ((result * MyResources_instance.playerCfg.scrollSpeed) << 6) / 10;
    int v11 = (MyResources_instance.playerCfg.scrollSpeed * this->f1098) << 6;
    *(DWORD *) &v17_action.f4 = (v11 / 10);
    v17_action._cpyFrF8 = this->_cpyToF10;
    v18_try_catch = 2;
    return this->pushAction(&v17_action);
}
