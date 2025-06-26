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

dk2::WindowCfg *EscOptions_LevelObjective_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 18, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2456, 1000, 0, 0, 2456, 1000, 0, NULL, dk2::CButton_render_4207E0, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_4289D0, dk2::CButton_render_428A30, 0x00000001, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_4288C0, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_4289D0, dk2::CButton_render_428A30, 0x00000003, 11, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 22, 1, 0x00000001, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, dk2::fun_f34_4289D0, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 21
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_EscOptions_LevelObjective, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
