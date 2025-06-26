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

    dk2::ButtonCfg Net_AddressBook_BtnArr[] {
        {
            BT_CTextInput, 428, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 480, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000000, 0x00000001, 0
        },
        {
            BT_CTextInput, 427, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 480, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000001, 0x00000001, 0
        },
        {
            BT_CTextInput, 425, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 480, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000002, 0x00000001, 0
        },
        {
            BT_CTextInput, 426, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 600, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000003, 0x00000001, 0
        },
        {
            BT_CTextInput, 423, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 600, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000004, 0x00000001, 0
        },
        {
            BT_CTextInput, 424, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 600, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000005, 0x00000001, 0
        },
        {
            BT_CTextInput, 422, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000014, 0,
            440, 720, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000006, 0x00000001, 0
        },
        {
            BT_CTextInput, 415, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000014, 0,
            960, 720, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000007, 0x00000001, 0
        },
        {
            BT_CTextInput, 416, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 720, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000008, 0x00000001, 0
        },
        {
            BT_CTextInput, 421, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 840, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000009, 0x00000001, 0
        },
        {
            BT_CTextInput, 414, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 840, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000A, 0x00000001, 0
        },
        {
            BT_CTextInput, 409, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 840, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000B, 0x00000001, 0
        },
        {
            BT_CTextInput, 420, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 960, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000C, 0x00000001, 0
        },
        {
            BT_CTextInput, 413, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 960, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000D, 0x00000001, 0
        },
        {
            BT_CTextInput, 408, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 960, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000E, 0x00000001, 0
        },
        {
            BT_CTextInput, 419, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 1080, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x0000000F, 0x00000001, 0
        },
        {
            BT_CTextInput, 412, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 1080, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000010, 0x00000001, 0
        },
        {
            BT_CTextInput, 407, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 1080, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000011, 0x00000001, 0
        },
        {
            BT_CTextInput, 418, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 1200, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000012, 0x00000001, 0
        },
        {
            BT_CTextInput, 411, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 1200, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000013, 0x00000001, 0
        },
        {
            BT_CTextInput, 406, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 1200, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000014, 0x00000001, 0
        },
        {
            BT_CTextInput, 417, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            440, 1320, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000015, 0x00000001, 0
        },
        {
            BT_CTextInput, 410, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000023, 0,
            960, 1320, 596, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000016, 0x00000001, 0
        },
        {
            BT_CTextInput, 405, 0, NULL, NULL, 0, 0, 0x00000000, 0x0000000A, 0,
            1544, 1320, 540, 104, 0, 0, 540, 104, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000002, 3, 0x00000017, 0x00000001, 0
        },
        {
            BT_CTextBox, 432, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 40, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 2, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 429, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            440, 288, 540, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 83, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 430, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            968, 288, 580, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 1559, 0x00000001, 0x00010000, 0
        },
        {
            BT_CTextBox, 431, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1544, 288, 540, 152, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 236, 0x00000002, 0x00010000, 0
        },
        {
            BT_CClickButton, 434, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 11, 1, 0x0000000B, 0x00000046, 0,
            2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Net_AddressBook_WinCfg {
        MWID_AddressBook, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Net_AddressBook_BtnArr, 2
    };
}

dk2::WindowCfg *Net_AddressBook_layout() {
    return &Net_AddressBook_WinCfg;
}

