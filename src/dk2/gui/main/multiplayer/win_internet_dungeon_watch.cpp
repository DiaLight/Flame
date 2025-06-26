//
// Created by DiaLight on 4/3/2025.
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

    dk2::ButtonCfg Net_InternetDungeonWatch_BtnArr[] {
        {
            BT_CTextBox, 683, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 472, 0, 0, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_54E740, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 575, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            668, 44, 1252, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 17, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 0, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 468, 524, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1393, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 571, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 468, 524, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1393, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 572, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            604, 468, 272, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 194, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 581, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            880, 468, 496, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 533, 0x00000003, 0x00010000, 0
        },
        {
            BT_CTextBox, 205, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 268, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 1688, 0x00000009, 0x00020000, 0
        },
        {
            BT_CTextInput, 584, 0, dk2::CTextInput_handleLeftClick_54EE10, NULL, 0, 0, 0x00000053, 0x0000000A, 0,
            1656, 440, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000000, 0x00000001, 0
        },
        {
            BT_CListBox, 580, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox__54EE50, (uint32_t) dk2::CListBox__54EE30, 0,
            72, 540, 1456, 620, 0, 0, 1456, 620, 0, dk2::CListBox_sub_530440, dk2::CListBox_render_546830, (uint32_t) dk2::CVerticalSlider_render_551490, 123, (uint32_t) &dk2::g_listItemNum, 0x00000040, 0
        },
        {
            BT_CTextBox, 579, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1168, 1600, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_546150, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 577, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000020, 0x00000061, 0,
            76, 1348, 632, 136, 0, 0, 632, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 159, 0x00000000, 0x000C0002, 0
        },
        {
            BT_CClickButton, 578, 0, dk2::CFrontEndComponent_static_sub_5457A0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            76, 1508, 632, 128, 0, 0, 632, 128, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 216, 0x00000001, 0x000C0002, 0
        },
        {
            BT_CClickButton, 670, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            76, 1508, 632, 128, 0, 0, 632, 128, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 2056, 0x00000002, 0x000C0002, 0
        },
        {
            BT_CClickButton, 576, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 3, 1, 0x00000003, 0x00000017, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CTextBox, 574, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            4, 260, 1080, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 157, 0x00000005, 0x00020002, 0
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Net_InternetDungeonWatch_WinCfg {
        MWID_InternetDungeonWatch, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::CWindow_fun, 0,
        0, 0, 0, 0, 0, Net_InternetDungeonWatch_BtnArr, 0
    };
}

dk2::WindowCfg *Net_InternetDungeonWatch_layout() {
    return &Net_InternetDungeonWatch_WinCfg;
}

