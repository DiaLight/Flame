//
// Created by DiaLight on 4/4/2025.
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

    dk2::ButtonCfg Skirmish_MapSelect_BtnArr[] {
        {
            BT_CTextBox, 474, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 40, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 9, 0x00000006, 0x00010000, 0
        },
        {
            BT_CTextBox, 231, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            80, 616, 1240, 640, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_541940, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 687, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 4, 4, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_537C30, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 468, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 272, 960, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_540600, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 470, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            80, 464, 640, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1544, 0x00000002, 0x00010001, 0
        },
        {
            BT_CTextBox, 471, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            672, 464, 320, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 194, 0x00000003, 0x00010000, 0
        },
        {
            BT_CTextBox, 472, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            960, 464, 380, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1545, 0x00000004, 0x00010000, 0
        },
        {
            BT_CListBox, 477, 0, dk2::CButton_handleLeftClick_5416E0, NULL, 0, 0, 0x00540B20, 0x00540A30, 0,
            80, 552, 1240, 608, 0, 0, 1240, 608, 0, dk2::CListBox_sub_530440, dk2::CButton_render_5410C0, (uint32_t) dk2::CVerticalSlider_render_551490, 75, (uint32_t) &dk2::g_idxLow_740348, 0x00000040, 0
        },
        {
            BT_CClickButton, 467, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000004F, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 529, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000004E, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Skirmish_MapSelect_WinCfg {
        MWID_Skirmish_MapSelect, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::__onMapSelected, 0,
        0, 0, 0, 0, 0, Skirmish_MapSelect_BtnArr, 2
    };
}

dk2::WindowCfg *Skirmish_MapSelect_layout() {
    return &Skirmish_MapSelect_WinCfg;
}

