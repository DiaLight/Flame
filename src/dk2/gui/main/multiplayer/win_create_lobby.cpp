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

    dk2::ButtonCfg Net_CreateLobby_BtnArr[] {
        {  // Title game name
            BT_CTextBox, 443, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 2560, 320, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54E8E0, 0x00000000, 0, 0x00000010, 0x00010000, 0
        },
        {  // my Ip addr
            BT_CTextBox, 466, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 300, 584, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_545C80, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {  // Map name
            BT_CTextBox, 456, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 272, 960, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53F8B0, 0x00000000, 32, 0x00000006, 0x00000001, 0
        },
        {
            BT_CTextBox, 687, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 4, 4, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_537C30, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {  // row 1 header "Player Name"
            BT_CTextBox, 449, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 460, 468, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1688, 0x00000000, 0x00000000, 0
        },
        {  // row 2 header "Allies"
            BT_CTextBox, 448, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            536, 460, 420, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 263, 0x00000000, 0x00000000, 0
        },
        {  // row 3 header "Ping"
            BT_CTextBox, 447, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            960, 460, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 195, 0x00000000, 0x00000000, 0
        },
        {  // row 4 header "RAM"
            BT_CTextBox, 445, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1124, 460, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1499, 0x00000000, 0x00000000, 0
        },
        {  // "Max Players"
            BT_CTextBox, 459, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 460, 960, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_546400, 0x00000000, 1492, 0x00000000, 0x00000000, 0
        },
        {  // Player selection
            BT_CListBox, 462, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox__5445C0, (uint32_t) dk2::Button_getPlayerDesc, 0,
            64, 536, 1328, 300, 0, 0, 1328, 300, 0, dk2::CListBox_sub_530440, dk2::Button_playersRenderTick, (uint32_t) CListBox__ret, 50, (uint32_t) &dk2::g_listItemNum, 0x00000000, 0
        },
        {  // "Kick Player"
            BT_CClickButton, 464, 0, dk2::Button_kickPlayer, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 1044, 560, 116, 0, 0, 560, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 270, 0x0000000A, 0x00030000, 0
        },
        {  // "Add Computer Player"
            BT_CClickButton, 528, 0, dk2::Button_addAiPlayer, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 1180, 1360, 116, 0, 0, 1360, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1547, 0x0000000B, 0x00030001, 0
        },
        {  // "Change map"
            BT_CClickButton, 454, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 33, 1, 0x00000021, 0x0000004D, 0,
            1480, 1180, 960, 116, 1, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1495, 0x0000000C, 0x00030002, 0
        },
        {  // "Random map"
            BT_CClickButton, 453, 0, dk2::CButton_handleLeftClick_randomMap, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1480, 1336, 960, 116, 0, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 1496, 0x0000000D, 0x00030002, 0
        },
        {  // "Game Settings"
            BT_CClickButton, 455, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 35, 1, 0x00000023, 0x00000048, 0,
            1480, 1484, 960, 116, 1, 0, 960, 116, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 2803, 0x0000000E, 0x00030002, 0
        },
        {  // Chat messages
            BT_CTextBox, 461, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 1352, 1244, 456, 0, 0, 1244, 456, 0, NULL, dk2::CButton_render_544FA0, 0x00550420, 0, 0x00000002, 0x00000000, 0
        },
        {  // Chat input
            BT_CTextInput, 460, 0, dk2::CButton_handleLeftClick_544E90, NULL, 0, 0, 0x00000000, 0x00000040, 0,
            64, 1796, 1192, 84, 0, 0, 1192, 84, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000000, 2, 0x00000000, 0x00010000, 0
        },
        {  // Exit
            BT_CClickButton, 463, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x00000052, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {  // Ready
            BT_CClickButton, 465, 0, dk2::CButton_handleLeftClick_545E10, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },
        {  // AI Difficulty
            BT_CClickButton, 681, 0, dk2::Button_changeAiType_leftClick, dk2::Button_changeAiType_rightClick, 0, 0, 0x00000000, 0x00000000, 0,
            624, 1044, 776, 108, 0, 0, 776, 108, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 0, 0x00000000, 0x00090001, 32
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Net_CreateLobby_WinCfg {
        MWID_CreateLobby, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::__onMapSelected, 0,
        0, 0, 0, 0, 0, Net_CreateLobby_BtnArr, 2
    };
}

dk2::WindowCfg *Net_CreateLobby_layout() {
    return &Net_CreateLobby_WinCfg;
}

