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
    dk2::ButtonCfg Main_LoadGame_BtnArr[] {
        {
            BT_CTextBox, 68, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 40, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 6, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 69, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            388, 288, 1012, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 83, 0x00000000, 0x00010001, 0
        },
        {
            BT_CTextBox, 70, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1400, 288, 460, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 2730, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 71, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1860, 288, 480, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 30, 0x00000000, 0x00010000, 0
        },
        {
            BT_CListBox, 72, 0, NULL, NULL, 0, 0, (uint32_t) dk2::static_DirFileList_instance2_saves_sav_getCount, (uint32_t) dk2::CListBox__530430, 0,
            280, 472, 2068, 968, 0, 0, 2088, 968, 0, dk2::CListBox_sub_530440, dk2::CListBox_LoadGame_SaveList_render, (uint32_t) dk2::CVerticalSlider_5520A0, 0, 0x00000000, (uint32_t) &dk2::g_listItemNum, 0
        },
        {
            BT_CClickButton, 74, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000013, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 10, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 73, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000007, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 9, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Main_LoadGame_WinCfg {
        MWID_LoadGame, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_LoadGame_BtnArr, 2
    };
}

dk2::WindowCfg *Main_LoadGame_layout() {
    return &Main_LoadGame_WinCfg;
}

