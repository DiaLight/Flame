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

dk2::WindowCfg *ActivePanel_KeeperSpells_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_417730, NULL, 0, 0, 0x00000001, 0x00000002, 0,
        0, 0, 64, 440, 24, 0, 6, 440, 0, dk2::fun_f34_410A60, dk2::CButton_render_4129E0, 0x0000000A, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_417730, NULL, 0, 0, 0xFFFFFFFF, 0x00000002, 0,
        0, 0, 64, 440, 24, 0, 6, 440, 0, dk2::fun_f34_410A60, dk2::CButton_render_4129E0, 0x0000000B, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_411140, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        0, 0, 256, 128, 0, 0, 212, 128, 0, dk2::fun_f34_4113B0, dk2::CButton_render_412FC0, 0x0000000E, 175, 0x00000000, 0x00000000, 5
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_KeeperSpells, 0, 1, 1828, 1452, 732, 468, 0, 0, 732, 468, 0, NULL, dk2::CWindow_getPanelItemsCount, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
