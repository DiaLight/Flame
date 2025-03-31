//
// Created by DiaLight on 4/3/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "main_layout.h"

namespace {

    dk2::ButtonCfg Main_Quit_BtnArr[] {
        {
            BT_CClickButton, 667, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000000, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },
        {
            BT_CClickButton, 668, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000000, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CTextBox, 684, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 420, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532390, 0x00000000, 0, 0x00000000, 0x00020000, 0
        },
        {
            BT_CTextBox, 686, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 632, 2560, 152, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 0, 0x00000000, 0x00000005, 0
        },
        {
            BT_CTextBox, 666, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 792, 2560, 460, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 0, 0x00000000, 0x00000005, 0
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Main_Quit_WinCfg {
        WID_Quit, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_Quit_BtnArr, 0
    };
}

dk2::WindowCfg *Main_Quit_layout() {
    return &Main_Quit_WinCfg;
}

