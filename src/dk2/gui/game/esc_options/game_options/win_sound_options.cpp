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

dk2::WindowCfg *GameOptions_SoundOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 95, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 160, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1457, 0x000000C6, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
        1460, 320, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_428F00, dk2::CButton_render_414750, 0x00000000, 0, 0x00000064, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429520, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 240, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_4293B0, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 400, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1459, 0x000000BC, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
        1460, 560, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_428F40, dk2::CButton_render_414750, 0x00000000, 0, 0x00000064, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429350, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 480, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_4291E0, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 400, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1458, 0x000000C5, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
        200, 560, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_428F80, dk2::CButton_render_414750, 0x00000000, 0, 0x00000064, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_4296E0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 480, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429570, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 160, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1460, 0x000000C4, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000064, 0,
        200, 320, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_428FC0, dk2::CButton_render_414750, 0x00000000, 0, 0x00000064, 0x00000040, 16
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 640, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1464, 0x000000C7, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429A70, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 720, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429890, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 800, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1674, 0x000000C9, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429C10, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 880, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429AA0, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 800, 1240, 72, 0, 0, 1240, 72, 0, dk2::fun_f34_429180, dk2::CButton_render_428A30, 0x00000000, 1472, 0x000000C8, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429160, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 880, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_428FF0, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 640, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1679, 0x000000D4, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429870, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1420, 720, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429700, 0x00000000, 0, 0x00000000, 0x00000001, 21
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
        GWID_GameOptions_SoundOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
