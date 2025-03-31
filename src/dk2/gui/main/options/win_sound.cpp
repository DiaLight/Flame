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

    dk2::ButtonCfg Options_Sound_BtnArr[] {
        {
            BT_CTextBox, 131, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            384, 12, 1684, 196, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 11, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 132, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            40, 428, 960, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1464, 0x00000000, 0x00030001, 0
        },
        {
            BT_CClickButton, 133, 0, dk2::CButton_handleLeftClick_54C810, dk2::CButton_handleRightClick_54C8C0, 0, 0, 0x00000085, 0x00000000, 0,
            820, 428, 496, 120, 0, 0, 496, 120, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00010001, 34
        },
        {
            BT_CTextBox, 134, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            40, 724, 960, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1674, 0x00000000, 0x00030001, 0
        },
        {
            BT_CClickButton, 135, 0, dk2::CButton_handleLeftClick_54C970, dk2::CButton_handleLeftClick_54C970, 0, 0, 0x00000087, 0x00000000, 0,
            800, 724, 516, 120, 0, 0, 516, 120, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00010001, 34
        },
        {
            BT_CTextBox, 138, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1284, 320, 804, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1460, 0x00000000, 0x00030002, 0
        },
        {
            BT_CHorizontalSlider, 139, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
            1532, 484, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B940, dk2::CButton_render_550D90, 0x00000001, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 140, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1284, 616, 804, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1457, 0x00000000, 0x00030002, 0
        },
        {
            BT_CHorizontalSlider, 141, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
            1532, 780, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B820, dk2::CButton_render_550D90, 0x00000001, 1, 0x00000000, 0x00000040, 0
        },
        {
            BT_CClickButton, 678, 0, dk2::CButton_handleLeftClick_54C9F0, dk2::CButton_handleLeftClick_54C9F0, 0, 0, 0x000002A6, 0x00000000, 0,
            2180, 616, 272, 120, 0, 0, 272, 120, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00010002, 32
        },
        {
            BT_CTextBox, 142, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1284, 912, 804, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1459, 0x00000000, 0x00030002, 0
        },
        {
            BT_CHorizontalSlider, 143, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
            1532, 1076, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B860, dk2::CButton_render_550D90, 0x00000001, 3, 0x00000000, 0x00000040, 27
        },
        {
            BT_CClickButton, 676, 0, dk2::CButton_handleLeftClick_54C9F0, dk2::CButton_handleLeftClick_54C9F0, 0, 0, 0x000002A4, 0x00000000, 0,
            2176, 912, 272, 120, 0, 0, 272, 120, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00010002, 32
        },
        {
            BT_CTextBox, 145, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1284, 1208, 804, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1458, 0x00000000, 0x00030002, 0
        },
        {
            BT_CHorizontalSlider, 144, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
            1532, 1372, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B8A0, dk2::CButton_render_550D90, 0x00000001, 4, 0x00000000, 0x00000040, 27
        },
        {
            BT_CClickButton, 677, 0, dk2::CButton_handleLeftClick_54C9F0, dk2::CButton_handleLeftClick_54C9F0, 0, 0, 0x000002A5, 0x00000000, 0,
            2180, 1208, 272, 120, 0, 0, 272, 120, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00010002, 32
        },
        {
            BT_CTextBox, 136, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            40, 1008, 960, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1679, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 137, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1160, 1004, 136, 136, 0, 0, 136, 136, 0, dk2::CButton_f34_54B910, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CTextBox, 675, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            40, 1304, 960, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1472, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 674, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1160, 1300, 136, 136, 0, 0, 136, 136, 0, dk2::CButton_f34_54B8E0, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CClickButton, 147, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000000, 0x0000001C, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 146, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000000, 0x0000001B, 0,
            2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Options_Sound_WinCfg {
        WID_Sound, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Options_Sound_BtnArr, 2
    };
}

dk2::WindowCfg *Options_Sound_layout() {
    return &Options_Sound_WinCfg;
}

