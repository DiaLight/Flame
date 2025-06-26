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

dk2::WindowCfg *GameOptions_ControlOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 98, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 160, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1469, 0x000000CA, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000010, 0,
        240, 240, 900, 64, 0, 0, 900, 64, 0, dk2::fun_f34_42AE90, dk2::CButton_render_414750, 0x00000000, 25, 0x00000190, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 320, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1468, 0x000000CB, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000005, 0x00000014, 0,
        240, 400, 900, 64, 0, 0, 900, 64, 0, dk2::fun_f34_42AF20, dk2::CButton_render_414750, 0x00000000, 25, 0x00000190, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 480, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 115, 0x000000CC, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000005, 0x00000014, 0,
        240, 560, 900, 64, 0, 0, 900, 64, 0, dk2::fun_f34_42AF50, dk2::CButton_render_414750, 0x00000000, 50, 0x000000C8, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 640, 1240, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 2840, 0x000000CD, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B280, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 720, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_42B110, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 640, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1670, 0x000000D0, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B410, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 720, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_42B2A0, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 800, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1470, 0x000000CE, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B0F0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 880, 1240, 176, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_42AF80, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 800, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1680, 0x000000D3, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42B5B0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 880, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_42B440, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 30, 1, 0x00000000, 0x00000000, 0,
        20, 980, 2520, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 117, 0x000000CF, 0x00000001, 21
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
        GWID_GameOptions_ControlOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
