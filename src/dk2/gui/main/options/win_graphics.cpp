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

    dk2::ButtonCfg Options_Graphics_BtnArr[] {
        {
            BT_CTextBox, 114, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            408, 4, 1712, 200, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 4, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 115, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            48, 388, 1164, 132, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1444, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 116, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1152, 384, 132, 136, 0, 0, 132, 136, 0, dk2::CButton_f34_54BA30, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CTextBox, 117, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            48, 636, 1164, 132, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1450, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 118, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1152, 632, 132, 136, 0, 0, 132, 136, 0, dk2::CButton_f34_54BA70, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CTextBox, 119, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            48, 864, 1244, 132, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 132, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 120, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1152, 864, 132, 136, 0, 0, 132, 136, 0, dk2::CButton_f34_54BA50, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CTextBox, 121, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            48, 1108, 572, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54CEC0, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 122, 0, dk2::CButton_handleLeftClick_54C540, dk2::CButton_handleRightClick_54C6B0, 0, 0, 0x0000007A, 0x00000000, 0,
            436, 1108, 820, 140, 0, 0, 820, 140, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000007, 0x00000001, 34
        },
        {
            BT_CTextBox, 123, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            48, 1348, 788, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 134, 0x00000000, 0x00030001, 0
        },
        {
            BT_CClickButton, 124, 0, dk2::ResolutionBtn_handleLeftClick_54C2A0, dk2::ResolutionBtn_handleRightClick_54C3F0, 0, 0, 0x0000007C, 0x00000000, 0,
            492, 1348, 820, 140, 0, 0, 820, 140, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00000001, 33
        },
        {
            BT_CTextBox, 125, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1440, 260, 1008, 136, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 135, 0x00000000, 0x00030000, 0
        },
        {
            BT_CHorizontalSlider, 126, 0, NULL, NULL, 0, 0, 0x0000000F, 0x0000003C, 0,
            1616, 432, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B9B0, dk2::CButton_render_550D90, 0x00000001, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 127, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1440, 736, 1008, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1445, 0x00000000, 0x00030000, 0
        },
        {
            BT_CHorizontalSlider, 128, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000003, 0,
            1616, 908, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54B980, dk2::CButton_render_550D90, 0x00000001, 1, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 679, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1440, 1216, 1008, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 96, 0x00000000, 0x00030000, 0
        },
        {
            BT_CClickButton, 680, 0, dk2::CButton_handleLeftClick_54D040, dk2::CButton_handleRightClick_54D0E0, 0, 0, 0x000002A8, 0x00000000, 0,
            1440, 1348, 1008, 140, 0, 0, 1008, 140, 0, NULL, dk2::CButton_render_532670, 0x00000000, 0, 0x00000000, 0x00000002, 33
        },
        {
            BT_CClickButton, 130, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000004, 0x0000001F, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 129, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000004, 0x0000001E, 0,
            2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Options_Graphics_WinCfg {
        WID_Graphics, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Options_Graphics_BtnArr, 2
    };
}

dk2::WindowCfg *Options_Graphics_layout() {
    return &Options_Graphics_WinCfg;
}

