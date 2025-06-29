//
// Created by DiaLight on 6/22/2025.
//

#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <memory>
#include <patches/gui/game/esc_options/btn_autosave.h>
#include <vector>

#include "../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *EscOptions_Save_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Title "Save"
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 201, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {  // Save list
        BT_CListBox, 2, 0, dk2::CButton_handleLeftClick_42A850, NULL, 0, 0, (uint32_t) dk2::CListBox_clickArg1_42A780, (uint32_t) dk2::CListBox_clickArg2_42A790, 0,
        20, 100, 920, 608, 0, 0, 920, 608, 0, dk2::CListBox_f34_411900, dk2::CButton_render_42A3B0, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 22
    };
    buttons.emplace_back() = {  // save name
        BT_CTextInput, 3, 0, dk2::CButton_handleLeftClick_42A920, NULL, 0, 0, 0x00000000, 0x0000000C, 0,
        20, 920, 920, 72, 0, 0, 920, 72, 0, NULL, dk2::CButton_render_428CD0, 0x00000000, 20, 0x00000001, 0x00000002, 0
    };
    buttons.emplace_back() = {  // Continue Game
        BT_CClickButton, 4, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {  // Back
        BT_CClickButton, 5, 0, NULL, NULL, 22, 1, 0x00000000, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 23
    };

    if (patch::autosave::enabled) {
        buttons.emplace_back() = patch::autosave::Save_AutosaveSwitch_btn(
            {1280, 100, 400, 72},
            {0, 0, 400, 72}
        );
        buttons.emplace_back() = patch::autosave::Save_KeepLastAutosavesSwitch_btn(
            {1800, 100, 400, 72},
            {0, 0, 400, 72}
        );
    }

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_EscOptions_Save, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
