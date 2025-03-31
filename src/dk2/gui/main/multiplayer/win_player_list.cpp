//
// Created by DiaLight on 4/3/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {


    dk2::ButtonCfg CreateLobby_PlayerList_BtnArr[] {
        {
            BT_CTextBox, 690, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 420, 2408, 260, 0, 0, 0, 0, 0, NULL, dk2::Button_renderPlayername, 0x00000000, 0, 0x00000001, 0x00000000, 0
        },
        {
            BT_CTextBox, 691, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 896, 2408, 140, 0, 0, 0, 0, 0, NULL, dk2::Button_renderPlayername, 0x00000000, 0, 0x00000002, 0x00000000, 0
        },
        {
            BT_CTextBox, 692, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 1056, 2408, 140, 0, 0, 0, 0, 0, NULL, dk2::Button_renderPlayername, 0x00000000, 0, 0x00000003, 0x00000000, 0
        },
        {
            BT_CTextBox, 693, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 1220, 2408, 140, 0, 0, 0, 0, 0, NULL, dk2::Button_renderPlayername, 0x00000000, 0, 0x00000004, 0x00000000, 0
        },
        {
            BT_CTextBox, 694, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 1380, 2408, 140, 0, 0, 0, 0, 0, NULL, dk2::Button_renderPlayername, 0x00000000, 0, 0x00000005, 0x00000000, 0
        },
        {
            BT_CClickButton, 695, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x00000075, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },

        EngOfButtonList,
    };

    dk2::WindowCfg CreateLobby_PlayerList_WinCfg {
        WID_PlayerList, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::__onMapSelected, 0,
        0, 0, 0, 0, 0, CreateLobby_PlayerList_BtnArr, 2
    };
}

dk2::WindowCfg *CreateLobby_PlayerList_layout() {
    return &CreateLobby_PlayerList_WinCfg;
}

