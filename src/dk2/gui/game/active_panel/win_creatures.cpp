//
// Created by DiaLight on 6/20/2025.
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

dk2::WindowCfg *ActivePanel_Creatures_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_417730, NULL, 0, 0, 0x00000001, 0x00000005, 0,
        288, 12, 64, 132, 24, 0, 6, 132, 0, dk2::fun_f34_410A60, dk2::CButton_render_4129E0, 0x0000000A, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_417730, NULL, 0, 0, 0xFFFFFFFF, 0x00000005, 0,
        288, 144, 64, 132, 24, 0, 6, 132, 0, dk2::fun_f34_410A60, dk2::CButton_render_4129E0, 0x0000000B, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000000, 0x00000000, 0,
        0, 4, 80, 72, 0, 0, 80, 68, 2308, NULL, NULL, 0x00000041, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_418080, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000001, 0x00000000, 0,
        72, 12, 120, 64, 0, 0, 120, 60, 0, dk2::fun_f34_418DD0, dk2::CButton_render_417850, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000000, 0x00000005, 0,
        0, 68, 80, 68, 0, 0, 80, 68, 2310, NULL, NULL, 0x00000038, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_418080, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000001, 0x00000005, 0,
        72, 72, 120, 64, 0, 0, 120, 64, 0, dk2::fun_f34_418DD0, dk2::CButton_render_417850, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000000, 0x00000006, 0,
        0, 132, 80, 72, 0, 0, 80, 72, 2312, NULL, NULL, 0x00000032, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 6, 0, dk2::CButton_handleLeftClick_418080, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000001, 0x00000006, 0,
        72, 136, 120, 64, 0, 0, 120, 64, 0, dk2::fun_f34_418DD0, dk2::CButton_render_417850, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000000, 0x00000004, 0,
        0, 196, 80, 72, 0, 0, 80, 72, 2314, NULL, NULL, 0x00000035, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 7, 0, dk2::CButton_handleLeftClick_418080, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000001, 0x00000004, 0,
        72, 200, 120, 64, 0, 0, 120, 64, 0, dk2::fun_f34_418DD0, dk2::CButton_render_417850, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_4177B0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        220, 16, 44, 52, 0, 0, 44, 52, 2316, NULL, dk2::CButton_render_417B40, 0x00000041, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_4177B0, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        220, 80, 44, 52, 0, 0, 44, 52, 2318, NULL, dk2::CButton_render_417B40, 0x00000032, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_4177B0, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        220, 144, 44, 52, 0, 0, 44, 52, 2320, NULL, dk2::CButton_render_417B40, 0x00000035, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_4177B0, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        220, 208, 44, 52, 0, 0, 44, 52, 2322, NULL, dk2::CButton_render_417B40, 0x00000032, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        368, 12, 64, 264, 0, 0, 64, 264, 0, NULL, dk2::CButton_render_4177D0, 0x0000009D, 1, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        4, 8, 64, 264, 0, 0, 64, 264, 0, NULL, dk2::CButton_render_4129E0, 0x0000009D, 1, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        208, 8, 64, 264, 0, 0, 64, 264, 0, NULL, dk2::CButton_render_4129E0, 0x000000A3, 1, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_Creatures, 0, 0, 0, 200, 432, 400, 0, 0, 432, 400, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
