//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <dk2_globals.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {
    dk2::ButtonCfg Multiplayer_IpxLocalNetwork_BtnArr[] {
        {
            BT_CTextBox, 682, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 472, 0, 0, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_54E740, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 197, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            668, 44, 1252, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 14, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 198, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            4, 260, 1080, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 157, 0x00000005, 0x00020002, 0
        },
        {
            BT_CTextBox, 685, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 624, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 1393, 0x0000000A, 0x00020000, 0
        },
        {
            BT_CTextInput, 230, 0, dk2::CTextInput_handleLeftClick_54EDF0, NULL, 0, 0, 0x00000053, 0x0000000A, 0,
            1656, 804, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000001, 0x00000001, 0
        },
        {
            BT_CTextBox, 205, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 268, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 1688, 0x00000009, 0x00020000, 0
        },
        {
            BT_CTextInput, 204, 0, dk2::CTextInput_handleLeftClick_54EE10, NULL, 0, 0, 0x00000053, 0x0000000A, 0,
            1656, 440, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000000, 0x00000001, 0
        },
        {
            BT_CTextBox, 202, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 468, 524, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1393, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 201, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            604, 468, 272, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 194, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 200, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            880, 468, 496, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 533, 0x00000003, 0x00010000, 0
        },
        {
            BT_CListBox, 203, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox_getLinesCount, (uint32_t) dk2::CListBox_selectLine, 0,
            72, 540, 1456, 620, 0, 0, 1456, 620, 0, dk2::CListBox_sub_530440, dk2::CListBox_renderTableStr, (uint32_t) dk2::CVerticalSlider_render_551490, 123, (uint32_t) &dk2::g_listItemNum, 0x00000040, 0
        },
        {
            BT_CTextBox, 210, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1168, 1600, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_546150, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 207, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000020, 0x00000021, 0,
            0, 1348, 792, 136, 0, 0, 792, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 159, 0x00000000, 0x000B0002, 0
        },
        {
            BT_CClickButton, 208, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000020, 0x00000020, 0,
            896, 1352, 632, 136, 0, 0, 632, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 158, 0x00000001, 0x000B0002, 0
        },
        {
            BT_CClickButton, 209, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 3, 1, 0x00000003, 0x00000017, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Multiplayer_IpxLocalNetwork_WinCfg {
        MWID_IpxLocalNetwork, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::CWindow_fun, 0,
        0, 0, 0, 0, 0, Multiplayer_IpxLocalNetwork_BtnArr, 2
    };
}

dk2::WindowCfg *Multiplayer_IpxLocalNetwork_layout() {
    return &Multiplayer_IpxLocalNetwork_WinCfg;
}

