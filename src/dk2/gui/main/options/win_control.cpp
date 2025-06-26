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

    dk2::ButtonCfg Options_Control_BtnArr[] {
        {
            BT_CTextBox, 148, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            540, 16, 1376, 188, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 12, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 673, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            4, 4, 0, 0, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54CE00, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 149, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            60, 264, 1288, 128, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532350, 0x00000000, 1477, 0x00000000, 0x00020001, 0
        },
        {
            BT_CTextBox, 672, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            60, 464, 1216, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 2845, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 671, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1280, 464, 1184, 76, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 2846, 0x00000000, 0x00010000, 0
        },
        {
            BT_CListBox, 150, 0, dk2::CButton_handleLeftClick_54BD70, dk2::CButton_handleLeftClick_54BD70, 0, 0, (uint32_t) dk2::CListBox_clickArg1_54BDE0, (uint32_t) dk2::CListBox_clickArg2_54BDF0, 0,
            60, 548, 2396, 388, 0, 0, 2396, 388, 0, dk2::CListBox_sub_530440, dk2::CListBox_render_54BE30, (uint32_t) dk2::CVerticalSlider_551BA0, 1, 0x00000001, 0x00000040, 0
        },
        {
            BT_CTextBox, 155, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            84, 976, 1120, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1466, 0x00000000, 0x00030000, 0
        },
        {
            BT_CHorizontalSlider, 156, 0, NULL, NULL, 0, 0, 0x00000005, 0x00000014, 0,
            276, 1152, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54BAF0, dk2::CButton_render_550D90, 0x00000001, 2, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 153, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1516, 976, 900, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1469, 0x00000000, 0x00030000, 0
        },
        {
            BT_CHorizontalSlider, 154, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000010, 0,
            1620, 1152, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54BAC0, dk2::CButton_render_550D90, 0x00000001, 1, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 157, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1516, 1340, 900, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 1468, 0x00000000, 0x00030000, 0
        },
        {
            BT_CHorizontalSlider, 158, 0, NULL, NULL, 0, 0, 0x00000005, 0x00000014, 0,
            1620, 1508, 680, 48, 0, 0, 680, 48, 0, dk2::CButton_f34_54BA90, dk2::CButton_render_550D90, 0x00000001, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 151, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            4, 1392, 1192, 288, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532330, 0x00000000, 2840, 0x00000000, 0x00030000, 0
        },
        {
            BT_CCheckBoxButton, 152, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1220, 1472, 128, 120, 0, 0, 128, 120, 0, dk2::CButton_f34_54BB20, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CClickButton, 160, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000000, 0x00000038, 0,
            2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 159, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 4, 1, 0x00000000, 0x00000039, 0,
            2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Options_Control_WinCfg {
        MWID_Control, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Options_Control_BtnArr, 2
    };
}

dk2::WindowCfg *Options_Control_layout() {
    return &Options_Control_WinCfg;
}

