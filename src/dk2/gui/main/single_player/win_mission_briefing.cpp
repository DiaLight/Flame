//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {
    dk2::ButtonCfg Map3d_MissionBriefing_BtnArr[] {
        {
            BT_CTextBox, 161, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 40, 2560, 208, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 1, 0x0000000C, 0x00010000, 0
        },
        {
            BT_CTextBox, 162, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 248, 2560, 180, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000000, 0x00000001, 0

        },
        {
            BT_CTextBox, 165, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 576, 1720, 296, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000000, 0x00000002, 0
        },
        {
            BT_CTextBox, 168, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 1104, 1720, 480, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000000, 0x00000003, 0
        },
        {
            BT_CTextBox, 164, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 436, 1720, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 1408, 0x00000006, 0x00020001, 0
        },
        {
            BT_CTextBox, 167, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 964, 1720, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 1409, 0x00000007, 0x00020001, 0
        },
        {
            BT_CClickButton, 169, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000000A, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 170, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x0000000C, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Map3d_MissionBriefing_WinCfg {
        WID_MissionBriefing, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Map3d_MissionBriefing_BtnArr, 2
    };
}

dk2::WindowCfg *Map3d_MissionBriefing_layout() {
    return &Map3d_MissionBriefing_WinCfg;
}

