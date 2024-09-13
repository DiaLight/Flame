//
// Created by DiaLight on 10.09.2024.
//
#include "dk2/CDefaultPlayerInterface.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "gog_patch.h"


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

    if(!control_windowed_mode::enabled) {
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


void dk2::CDefaultPlayerInterface::createSurfacesForView_42CDF0(RtGuiView *view) {
    CBridge *f10_c_bridge = this->profiler->c_bridge;
    char *rowPos = (char *) view->surf.lpSurface;
    int v4_bytesPerPix = view->dwRGBBitCount / 8;
    int v13_lineSize = 32 * view->surf.lPitch;
    char *v10__allyWindowText = (char *) view->surf.lpSurface;
    for(unsigned int y = 0; y < view->height_32blocks; ++y) {
        char *linePos = rowPos;
        for(unsigned int x = 0; x < view->width_128blocks; ++x) {
            int lPitch = view->surf.lPitch;
            Pos2i v14_size;
            v14_size.x = 128;
            v14_size.y = 32;
            MySurface v15_surf;
            v15_surf.constructor(&v14_size, &view->surf.desc, linePos, lPitch);
            int _idx = x + view->width_128blocks * y;
            if(gog::RtGuiView_fix::enable) {
                if(idx >= 93 && view == &dk2::CDefaultPlayerInterface_instance._allyWindowText) {
                    idx = 0;
                }
            }
            int _id = view->Arrp31x400_ids[_idx];
            f10_c_bridge->v_f68(_id, &v15_surf, 1);
            linePos += v4_bytesPerPix * 128;
        }
        rowPos = &v10__allyWindowText[v13_lineSize];
        v10__allyWindowText += v13_lineSize;
    }
}


