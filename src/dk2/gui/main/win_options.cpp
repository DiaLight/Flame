//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "main_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *Main_Options_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 109, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        464, 24, 1600, 232, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 10, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 110, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x000F0004, 0x001D0000, 0,
        608, 416, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 96, 0x00000000, 0x00060002, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 111, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00100004, 0x001A0001, 0,
        608, 596, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 95, 0x00000001, 0x00060002, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 112, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00110004, 0x003A0002, 0,
        608, 776, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 98, 0x00000002, 0x00060002, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 113, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 1, 0x00000000, 0x00FF000F, 0,
        2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000004, 0x00000000, 35
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        MWID_Options, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 2
    };
    return window.get();
}

