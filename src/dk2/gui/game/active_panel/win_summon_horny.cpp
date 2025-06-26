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

dk2::WindowCfg *ActivePanel_SummonHorny_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_424F50, dk2::CButton_handleRightClick_424FB0, 0, 0, 0x00000000, 0x00000000, 0,
        0, 12, 264, 264, 0, 0, 264, 264, 2235, dk2::fun_f34_424FD0, dk2::CButton_render_424840, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_SummonHorny, 1, 0, 2272, 1600, 288, 432, 0, 0, 288, 432, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
