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

dk2::WindowCfg *Misc_DropDownList_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CListBox, 3, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox_clickArg1_4286D0, (uint32_t) dk2::CListBox_clickArg2_4286E0, 0,
        0, 0, 400, 600, 0, 0, 400, 600, 0, dk2::CListBox_f34_411900, dk2::CButton_render_428450, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 22
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Misc_DropDownList, 0, 0, 0, 400, 400, 600, 0, 0, 400, 600, 0, dk2::CWindow_sub_417EA0, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
