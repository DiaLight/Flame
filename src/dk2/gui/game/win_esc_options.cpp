//
// Created by DiaLight on 6/22/2025.
//

#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2/button/button_types.h>
#include <memory>
#include <vector>
#include "game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *X_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {};

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {};
    return window.get();
}

dk2::WindowCfg *Game_EscOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 94, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 33, 1, 0x00000000, 0x00000000, 0,
        20, 160, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428C30, 0x00000000, 537, 0x000000B7, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 25, 1, 0x00000000, 0x00000000, 0,
        20, 320, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1265, 0x000000B6, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42A760_collectSaves, NULL, 23, 1, 0x00000000, 0x00000000, 0,
        20, 480, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_42A360, dk2::CButton_render_428A30, 0x00000000, 143, 0x000000B4, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42A760_collectSaves, NULL, 24, 1, 0x00000000, 0x00000000, 0,
        20, 640, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_42A360, dk2::CButton_render_428A30, 0x00000000, 201, 0x000000B5, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 34, 1, 0x00000000, 0x00000000, 0,
        1280, 160, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1266, 0x000000B8, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_420570_exitGame, NULL, 35, 1, 0x00000002, 0x000004F5, 0,
        1280, 320, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1269, 0x000000D1, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 142, 0x000000C7, 0x00000001, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_EscOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
