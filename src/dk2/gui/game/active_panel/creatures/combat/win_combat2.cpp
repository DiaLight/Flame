//
// Created by DiaLight on 6/20/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../../../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *Creatures_Combat2_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_418080, dk2::CButton_handleRightClick_417F60, 0, 0, 0x00000002, 0x00000016, 0,
        220, 140, 128, 128, 0, 0, 128, 80, 0, dk2::fun_f34_418DD0, dk2::CButton_render_417850, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Creatures_Combat2, 0, 1, 0, 1452, 980, 468, 0, 0, 732, 468, 0, NULL, dk2::CWindow_getPanelItemsCount, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
