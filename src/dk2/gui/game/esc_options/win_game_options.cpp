//
// Created by DiaLight on 6/22/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *EscOptions_GameOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Title "Game Options"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 97, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {  // Graphics options
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429C30, NULL, 26, 1, 0x00000000, 0x00000000, 0,
        20, 160, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 96, 0x000000BB, 0x00000001, 21
    };
    buttons.emplace_back() = {  // Sound options
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428E90, NULL, 27, 1, 0x00000000, 0x00000000, 0,
        1280, 160, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 95, 0x000000BC, 0x00000001, 21
    };
    buttons.emplace_back() = {  // Control options
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42AE40, NULL, 29, 1, 0x00000000, 0x00000000, 0,
        20, 480, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 98, 0x000000BD, 0x00000001, 0
    };
    buttons.emplace_back() = {  // Define user cameras
        BT_CClickButton, 3, 0, NULL, NULL, 31, 1, 0x00000000, 0x00000000, 0,
        1280, 480, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_42B710, dk2::CButton_render_428A30, 0x00000000, 1485, 0x000000BE, 0x00000001, 21
    };
    buttons.emplace_back() = {  // Continue game
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {  // Back
        BT_CClickButton, 3, 0, NULL, NULL, 22, 1, 0x00000000, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_EscOptions_GameOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
