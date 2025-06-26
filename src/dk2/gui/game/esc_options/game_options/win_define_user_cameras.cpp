//
// Created by DiaLight on 6/22/2025.
//

#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2/button/button_types.h>
#include <memory>
#include <vector>
#include "../../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *GameOptions_DefineUserCameras_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 1485, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B5D0, NULL, 32, 1, 0x00000000, 0x00000000, 0,
        20, 160, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1486, 0x000000BE, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B5D0, NULL, 32, 1, 0x00000001, 0x00000000, 0,
        20, 320, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1487, 0x000000BE, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B5D0, NULL, 32, 1, 0x00000002, 0x00000000, 0,
        20, 480, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1488, 0x000000BE, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 25, 1, 0x00000000, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_DefineUserCameras, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
