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

    void __cdecl CListBox__ret(dk2::CVerticalSlider *, dk2::CFrontEndComponent *) {}

    dk2::ButtonCfg Main_Scirmish_BtnArr[] {
        {
            BT_CTextBox, 443, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            188, 36, 2152, 184, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 15, 0x00000010, 0x00010000, 0
        },
        {
            BT_CTextBox, 104, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 300, 584, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_545C80, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 456, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 272, 960, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53F8B0, 0x00000000, 9, 0x00000006, 0x00000001, 0
        },
        {
            BT_CTextBox, 687, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 4, 4, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_537C30, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 449, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 460, 468, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1688, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 459, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 460, 960, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_546400, 0x00000000, 1492, 0x00000000, 0x00000000, 0
        },
        {
            BT_CListBox, 86, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox__5445C0, (uint32_t) dk2::Button_getPlayerDesc, 0,
            64, 536, 1328, 300, 0, 0, 1328, 300, 0, dk2::CListBox_sub_530440, dk2::Button_playersRenderTick, (uint32_t) CListBox__ret, 50, (uint32_t) &dk2::g_listItemNum, 0x00000000, 0
        },
        {
            BT_CClickButton, 464, 0, dk2::Button_kickPlayer, NULL, 0, 0, 0xFFFFFFFF, 0x00000000, 0,
            64, 1044, 800, 116, 0, 0, 800, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 270, 0x0000000A, 0x00090000, 32
        },
        {
            BT_CClickButton, 528, 0, dk2::Button_addAiPlayer, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 1180, 1360, 116, 0, 0, 1360, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1547, 0x0000000B, 0x00090001, 32
        },
        {
            BT_CClickButton, 454, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 34, 1, 0x00000022, 0x00000058, 0,
            1480, 1180, 960, 116, 1, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1495, 0x0000000C, 0x00090002, 32
        },
        {
            BT_CClickButton, 453, 0, dk2::CButton_handleLeftClick_5463B0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 1336, 960, 116, 0, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1496, 0x0000000D, 0x00090002, 32
        },
        {
            BT_CClickButton, 78, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 35, 1, 0x00000023, 0x00000057, 0,
            1480, 1484, 960, 116, 1, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 2803, 0x0000000E, 0x00090002, 32
        },
        {
            BT_CClickButton, 76, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000018, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 533, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000005A, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },
        {
            BT_CClickButton, 681, 0, dk2::Button_changeAiType_leftClick, dk2::Button_changeAiType_rightClick, 0, 0, 0x00000000, 0x00000000, 0,
            624, 1044, 776, 108, 0, 0, 776, 108, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 0, 0x00000000, 0x00090001, 32
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Main_Scirmish_WinCfg {
        MWID_Scirmish, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_Scirmish_BtnArr, 2
    };
}

dk2::WindowCfg *Main_Scirmish_layout() {
    return &Main_Scirmish_WinCfg;
}

