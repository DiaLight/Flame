//
// Created by DiaLight on 6/22/2025.
//

#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2/button/button_types.h>
#include <memory>
#include <vector>
#include "../../../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *GameOptions_AdvancedSoundOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Title "Advanced Sound Options"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 2520, 72, 0, 0, 2520, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 1500, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {  // Back
        BT_CClickButton, 3, 0, NULL, NULL, 27, 1, 0x00000000, 0x00000000, 0,
        20, 1100, 2520, 72, 0, 0, 2520, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x00000001, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_SoundOptions_AdvancedSoundOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
