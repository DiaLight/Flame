//
// Created by DiaLight on 4/3/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {
    dk2::ButtonCfg Map3d_BtnArr[] {
        {
            BT_CTextBox, 0, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536FA0, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 534, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000025, 0x00000059, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Map3d_WinCfg {
        WID_Map3d, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Map3d_BtnArr, 3
    };
}

dk2::WindowCfg *Map3d_layout() {
    return &Map3d_WinCfg;
}

