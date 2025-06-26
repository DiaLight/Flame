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

dk2::WindowCfg *Misc_GeneralError_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 20, 1600, 600, 0, 0, 1600, 600, 0, NULL, dk2::CButton_render_422660, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, NULL, NULL, 0, 1, 0x00000000, 0x00000000, 0,
        540, 632, 256, 128, 0, 0, 256, 128, 0, NULL, dk2::CButton_render_4129E0, 0x00000043, 0, 0x00000000, 0x00000000, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Misc_GeneralError, 0, 0, 700, 200, 1664, 760, 0, 0, 1664, 760, 0, dk2::CWindow_sub_417EA0, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
