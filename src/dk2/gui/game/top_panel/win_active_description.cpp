//
// Created by DiaLight on 6/24/2025.
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

dk2::WindowCfg *TopPanel_ActiveDescription_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 0, 1440, 88, 0, 0, 1440, 88, 0, NULL, dk2::CButton_render_42E140, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_TopPanel_ActiveDescription, 1, 0, 1020, 20, 1540, 88, 0, 0, 1540, 88, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
