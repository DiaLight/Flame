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

    dk2::ButtonCfg MissionDebriefing_StatsShort_BtnArr[] {
        {
            BT_CTextBox, 177, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 48, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 18, 0x00000001, 0x00010000, 0
        },
        {
            BT_CTextBox, 162, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 248, 2560, 180, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000001, 0x00000001, 0
        },
        {
            BT_CTextBox, 165, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 576, 1720, 296, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000001, 0x00000002, 0
        },
        {
            BT_CTextBox, 168, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            764, 1104, 1720, 480, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53A280, 0x00000000, 0, 0x00000001, 0x00000003, 0
        },
        {
            BT_CTextBox, 179, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            216, 576, 1800, 580, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53CAF0, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 180, 90, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            760, 968, 1500, 512, 0, 0, 1600, 512, 0, NULL, dk2::CButton_render_53D270, 0x00551BA0, 0, 0x00000002, 0x00000000, 0
        },
        {
            BT_CClickButton, 181, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000055, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000003, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg MissionDebriefing_StatsShort_WinCfg {
        MWID_MissionDebriefing_StatsShort, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, MissionDebriefing_StatsShort_BtnArr, 2
    };
}

dk2::WindowCfg *MissionDebriefing_StatsShort_layout() {
    return &MissionDebriefing_StatsShort_WinCfg;
}

