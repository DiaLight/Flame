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

dk2::WindowCfg *Main_SinglePlayer_layout() {
    if (window) return window.get();

    buttons.emplace_back() = { // Single Player Game title
        BT_CTextBox, 591, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        464, 24, 1600, 232, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, NULL, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = { // New Campaign
        BT_CClickButton, 6, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000002, 0x00000001, 0,
        616, 408, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 140, 0x00000000, 0x00050002, 32
    };
    buttons.emplace_back() = { // Continue Campaign
        BT_CClickButton, 567, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000002, 0x0001000D, 0,
        616, 588, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 2059, 0x00000001, 0x00050002, 32
    };
    buttons.emplace_back() = { // Skirmish
        BT_CClickButton, 8, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000002, 0x0002000A, 0,
        616, 852, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 141, 0x00000002, 0x00050002, 32
    };
    buttons.emplace_back() = { // Load Game
        BT_CClickButton, 7, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000002, 0x00030007, 0,
        616, 1032, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 145, 0x00000003, 0x00050002, 32
    };
    buttons.emplace_back() = { // X (Back)
        BT_CClickButton, 9, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 1, 1, 0x00010002, 0x00040000, 0,
        2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, NULL, 0, 0x00000004, 0x00000000, 36
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        WID_SinglePlayer, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 1
    };
    return window.get();
}

