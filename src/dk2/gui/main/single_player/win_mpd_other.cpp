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
    dk2::ButtonCfg MyPetDungeon_Other_BtnArr[] {
        {
            BT_CTextBox, 562, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 44, 2560, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 21, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 231, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            620, 616, 1240, 640, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTableBackground_541980, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 470, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            640, 464, 640, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1544, 0x00000002, 0x00010001, 0
        },
        {
            BT_CTextBox, 472, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1540, 464, 380, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1545, 0x00000004, 0x00010000, 0
        },
        {
            BT_CListBox, 696, 0, dk2::CButton_handleLeftClick_5417F0, NULL, 0, 0, (uint32_t) dk2::CListBox__540B70, (uint32_t) dk2::CListBox__get_wstr19, 0,
            640, 552, 1240, 608, 0, 0, 1240, 608, 0, dk2::CListBox_sub_530440, dk2::CButton_render_542110, (uint32_t) dk2::CVerticalSlider_render_551490, 75, (uint32_t) &dk2::g_idxLow_740348, 0x00000040, 0
        },
        {
            BT_CClickButton, 564, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 38, 1, 0x00000000, 0x00000060, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000001, 0x00000000, 36
        },
        {
            BT_CClickButton, 565, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000005F, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg MyPetDungeon_Other_WinCfg {
        MWID_MyPetDungeon_Other, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, MyPetDungeon_Other_BtnArr, 4
    };
}

dk2::WindowCfg *MyPetDungeon_Other_layout() {
    return &MyPetDungeon_Other_WinCfg;
}

