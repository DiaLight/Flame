//
// Created by DiaLight on 6/24/2025.
//

#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2/button/button_types.h>
#include <memory>
#include <vector>
#include "../../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *Counters_MpdSlapsRemaining_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 0, 256, 128, 0, 0, 256, 128, 1681, NULL, dk2::CButton_render_427870, 0x00000108, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Counters_MpdSlapsRemaining, 1, 0, 1352, 1320, 256, 128, 0, 0, 256, 128, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
