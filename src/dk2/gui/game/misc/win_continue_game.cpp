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

dk2::WindowCfg *Misc_ContinueGame_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_4281D0, NULL, 0, 1, 0x00000000, 0x00000000, 4,
        88, 20, 88, 88, 0, 0, 88, 88, 0, NULL, dk2::CButton_render_4129E0, 0x0000008E, 1, 0x00000000, 0x00000000, 24
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_428230, NULL, 0, 1, 0x00000000, 0x00000000, 4,
        264, 20, 88, 88, 0, 0, 88, 88, 0, NULL, dk2::CButton_render_4129E0, 0x000000A7, 1, 0x00000000, 0x00000000, 23
    };
    buttons.emplace_back() = {
        BT_CTextBox, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 20, 1096, 144, 0, 0, 1096, 144, 0, NULL, dk2::CButton_render_428250, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Misc_ContinueGame, 0, 0, 880, 400, 1200, 220, 0, 0, 1200, 220, 0, dk2::CWindow_sub_417EA0, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
