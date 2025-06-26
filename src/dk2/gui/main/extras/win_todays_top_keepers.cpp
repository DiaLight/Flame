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

    dk2::ButtonCfg Extras_TodaysTopKeepers_BtnArr[] {
        {
            BT_CTextBox, 25, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 64, 2560, 384, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 5, 0x0000000A, 0x00010000, 0
        },
        {
            BT_CTextBox, 26, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 360, 2560, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x0000000A, 0x00000000, 0
        },
        {
            BT_CTextBox, 27, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 500, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 28, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 620, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000001, 0x00000000, 0
        },
        {
            BT_CTextBox, 29, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 740, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000002, 0x00000000, 0
        },
        {
            BT_CTextBox, 30, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 860, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000003, 0x00000000, 0
        },
        {
            BT_CTextBox, 31, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 980, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000004, 0x00000000, 0
        },
        {
            BT_CTextBox, 32, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1100, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000005, 0x00000000, 0
        },
        {
            BT_CTextBox, 33, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1220, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000006, 0x00000000, 0
        },
        {
            BT_CTextBox, 34, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1340, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000007, 0x00000000, 0
        },
        {
            BT_CTextBox, 35, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1460, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000008, 0x00000000, 0
        },
        {
            BT_CTextBox, 36, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1580, 2560, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53DBD0, 0x00000000, 0, 0x00000009, 0x00000000, 0
        },
        {
            BT_CTextInput, 37, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 500, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000000, 0x00000000, 32
        },
        {
            BT_CTextInput, 38, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 620, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000001, 0x00000000, 32
        },
        {
            BT_CTextInput, 39, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 740, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000002, 0x00000000, 32
        },
        {
            BT_CTextInput, 40, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 860, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000003, 0x00000000, 32
        },
        {
            BT_CTextInput, 41, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 980, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000004, 0x00000000, 32
        },
        {
            BT_CTextInput, 42, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 1100, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000005, 0x00000000, 32
        },
        {
            BT_CTextInput, 43, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 1220, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000006, 0x00000000, 32
        },
        {
            BT_CTextInput, 44, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 1340, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000007, 0x00000000, 32
        },
        {
            BT_CTextInput, 45, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 1460, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000008, 0x00000000, 32
        },
        {
            BT_CTextInput, 46, 0, NULL, NULL, 0, 0, 0x00000000, 0xFFFFFFFF, 0,
            1640, 1580, 800, 96, 0, 0, 800, 96, 0, NULL, dk2::CTextInput_render_52FF10, 0x00010000, 3, 0x00000009, 0x00000000, 32
        },
        {
            BT_CClickButton, 47, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000041, 0,
            2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Extras_TodaysTopKeepers_WinCfg {
        MWID_TodaysTopKeepers, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Extras_TodaysTopKeepers_BtnArr, 2
    };
}

dk2::WindowCfg *Extras_TodaysTopKeepers_layout() {
    return &Extras_TodaysTopKeepers_WinCfg;
}

