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

    dk2::ButtonCfg Extras_Credits_BtnArr[] {
        {
            BT_CTextBox, 586, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            628, 40, 1308, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 20, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 588, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            356, 300, 1800, 1176, 0, 0, 1800, 1176, 0, NULL, dk2::CButton_sub_53AF80, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 587, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000062, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Extras_Credits_WinCfg {
        MWID_Credits, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Extras_Credits_BtnArr, 2
    };
}

dk2::WindowCfg *Extras_Credits_layout() {
    return &Extras_Credits_WinCfg;
}

