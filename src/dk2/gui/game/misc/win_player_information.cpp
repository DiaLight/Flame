//
// Created by DiaLight on 6/23/2025.
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

dk2::WindowCfg *Misc_PlayerInformation_layout() {  // "I" key in game
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 18, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 200, 1992, 812, 0, 0, 1992, 812, 0, NULL, dk2::CButton_render_423450, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        280, 40, 128, 128, 0, 0, 128, 128, 1518, NULL, dk2::CButton_render_4129E0, 0x00000065, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        440, 40, 128, 128, 0, 0, 128, 128, 1519, NULL, dk2::CButton_render_4129E0, 0x00000063, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        600, 40, 128, 128, 0, 0, 128, 128, 1520, NULL, dk2::CButton_render_4129E0, 0x00000069, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        760, 40, 128, 128, 0, 0, 128, 128, 1521, NULL, dk2::CButton_render_4129E0, 0x00000066, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        920, 40, 128, 128, 0, 0, 128, 128, 1522, NULL, dk2::CButton_render_4129E0, 0x00000062, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1080, 40, 128, 128, 0, 0, 128, 128, 1523, NULL, dk2::CButton_render_4129E0, 0x00000075, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1240, 40, 128, 128, 0, 0, 128, 128, 1524, NULL, dk2::CButton_render_4129E0, 0x00000068, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1400, 40, 128, 128, 0, 0, 128, 128, 1525, NULL, dk2::CButton_render_4129E0, 0x00000073, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1560, 40, 128, 128, 0, 0, 128, 128, 1526, NULL, dk2::CButton_render_4129E0, 0x00000074, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1720, 40, 128, 128, 0, 0, 128, 128, 1527, NULL, dk2::CButton_render_4129E0, 0x00000064, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1880, 40, 128, 128, 0, 0, 128, 128, 1528, NULL, dk2::CButton_render_4129E0, 0x00000067, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_423360, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        40, 1032, 128, 128, 0, 0, 128, 128, 0, NULL, dk2::CButton_render_4129E0, 0x000000C7, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Misc_PlayerInformation, 0, 0, 80, 200, 2056, 1160, 0, 0, 2056, 1160, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
