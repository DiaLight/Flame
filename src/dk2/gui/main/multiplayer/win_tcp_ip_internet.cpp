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

    dk2::ButtonCfg Multiplayer_TcpIpInternet_BtnArr[] {
        {
            BT_CTextBox, 231, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 472, 0, 0, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_54E740, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 214, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            668, 44, 1252, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 13, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 228, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 624, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 1393, 0x0000000A, 0x00020000, 0
        },
        {
            BT_CTextInput, 227, 0, dk2::CTextInput_handleLeftClick_54EDF0, NULL, 0, 0, 0x00000053, 0x0000000A, 0,
            1656, 804, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000001, 0x00000001, 0
        },
        {
            BT_CTextBox, 222, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 260, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 1688, 0x00000009, 0x00020000, 0
        },
        {
            BT_CTextInput, 221, 0, dk2::CTextInput_handleLeftClick_54EE10, NULL, 0, 0, 0x00000053, 0x0000000A, 0,
            1656, 440, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000000, 0x00000001, 0
        },
        {
            BT_CTextBox, 531, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1656, 988, 860, 124, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 236, 0x0000000E, 0x00020000, 0
        },
        {
            BT_CTextInput, 530, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000005, 0,
            1656, 1160, 860, 104, 0, 0, 860, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 5, 0x00000003, 0x00000001, 32
        },
        {
            BT_CTextBox, 215, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            4, 260, 1080, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_render_532370, 0x00000000, 157, 0x00000005, 0x00020002, 0
        },
        {
            BT_CTextBox, 219, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 468, 524, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1393, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 218, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            604, 468, 272, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 194, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 217, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            880, 468, 496, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 533, 0x00000003, 0x00010000, 0
        },
        {
            BT_CListBox, 220, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox_getLinesCount, (uint32_t) dk2::CListBox_selectLine, 0,
            72, 540, 1456, 620, 0, 0, 1456, 620, 0, dk2::CListBox_sub_530440, dk2::CListBox_renderTableStr, (uint32_t) dk2::CVerticalSlider_render_551490, 0, (uint32_t) &dk2::g_listItemNum, 0x00000040, 0
        },
        {  // status line
            BT_CTextBox, 532, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1168, 1600, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_546150, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {  // "Join"
            BT_CClickButton, 224, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000020, 0x00000054, 0,
            76, 1352, 632, 136, 0, 0, 632, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 159, 0x00000000, 0x000A0002, 0
        },
        {  // "CancelRefresh"
            BT_CClickButton, 223, 0, dk2::CFrontEndComponent_static_sub_5457A0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1512, 792, 136, 0, 0, 792, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 216, 0x00000001, 0x000A0002, 0
        },
        {
            BT_CClickButton, 670, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1512, 792, 136, 0, 0, 792, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 2056, 0x00000002, 0x000A0002, 0
        },
        {  // "Create"
            BT_CClickButton, 225, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000020, 0x00000053, 0,
            756, 1352, 872, 136, 0, 0, 872, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 158, 0x00000003, 0x000A0002, 0
        },
        {  // "Address Book"
            BT_CClickButton, 213, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 30, 1, 0x0000001E, 0x00000056, 0,
            756, 1512, 872, 136, 1, 0, 872, 136, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1403, 0x00000004, 0x000A0002, 0
        },
        {
            BT_CClickButton, 226, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 3, 1, 0x00000003, 0x00000017, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Multiplayer_TcpIpInternet_WinCfg {
        MWID_TcpIpInternet, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::CWindow_fun, 0,
        0, 0, 0, 0, 0, Multiplayer_TcpIpInternet_BtnArr, 2
    };
}

dk2::WindowCfg *Multiplayer_TcpIpInternet_layout() {
    return &Multiplayer_TcpIpInternet_WinCfg;
}

