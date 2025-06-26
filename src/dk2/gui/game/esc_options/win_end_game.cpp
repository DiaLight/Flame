//
// Created by DiaLight on 6/22/2025.
//

#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2/button/button_types.h>
#include <memory>
#include <vector>
#include "../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *EscOptions_EndGame_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 1266, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_420570_exitGame, NULL, 35, 1, 0x00000001, 0x0000000C, 0,
        20, 160, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428C60, 0x00000000, 12, 0x000000B8, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_420570_exitGame, NULL, 35, 1, 0x00000003, 0x0000000D, 0,
        20, 320, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 13, 0x000000D2, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 22, 1, 0x00000000, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_EscOptions_ExitGame, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
