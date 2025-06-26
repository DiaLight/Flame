//
// Created by DiaLight on 6/22/2025.
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

dk2::WindowCfg *TopPanel_InfoAndChat_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Multiplayer chat input
            BT_CTextInput, 3, 0, dk2::CButton_handleLeftClick_426000, NULL, 0, 0, 0x00000000, 0x00000080, 0,
            0, 160, 2560, 80, 0, 0, 2560, 80, 0, NULL, dk2::CButton_render_4263E0, 0x00000000, 20, 0x00000001, 0x00000000, 0
    };
    buttons.emplace_back() = {  // Dungeon heart health
        BT_CClickButton, 1, 0, NULL, dk2::CButton_handleRightClick_416680, 0, 0, 0x00000000, 0x00000000, 0,
        28, 28, 100, 100, 0, 0, 100, 100, 2139, NULL, NULL, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Mana
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        140, 0, 360, 88, 0, 0, 360, 88, 2133, NULL, NULL, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Payday countdown
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        540, 28, 100, 100, 0, 0, 100, 100, 2143, NULL, NULL, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Gold Count
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_416730, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        680, 0, 400, 88, 0, 0, 400, 88, 2141, NULL, dk2::CButton_render_414BC0, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_TopPanel_InfoAndChat, 1, 0, 0, 20, 1020, 88, 0, 0, 1020, 88, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
