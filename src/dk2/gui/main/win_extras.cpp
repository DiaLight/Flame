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

dk2::WindowCfg *Main_Extras_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 592, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        464, 40, 1600, 232, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 7, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 19, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00120006, 0x003D0000, 0,
        616, 428, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 2802, 0x00000000, 0x00070002, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 22, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00050006, 0x003B0001, 0,
        616, 576, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 93, 0x00000001, 0x00070002, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 21, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00060006, 0x003E0002, 0,
        616, 888, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 86, 0x00000002, 0x00070002, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 23, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, 0x00000006, 0x00630003, 0,
        616, 1040, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CClickButton_render_532670, 0x00000000, 372, 0x00000003, 0x00070002, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 24, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 1, 0x00000006, 0x00FF0010, 0,
        2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000004, 0x00070002, 35
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        MWID_Extras, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 2
    };
    return window.get();
}

