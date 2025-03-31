//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <dk2_globals.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "main_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *Main_Multiplayer_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 13, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 52, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, NULL, 16, 0x00000000, 0x00010000, 0
    };
    buttons.emplace_back() = {
        BT_CListBox, 12, 0, NULL, NULL, 0, 0, (uint32_t) dk2::getListElementCount, (uint32_t) dk2::CListBox_listfun, 0,
        0, 400, 2560, 460, 0, 0, 2560, 460, 0, dk2::CListBox_sub_530440, dk2::CListBox_sub_54EA90, (uint32_t) dk2::CVerticalSlider_render_54FF00, 0, (uint32_t) &dk2::g_listItemNum, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 18, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000016, 0,
        2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, NULL, 0, 0x00000000, 0x00000000, 36
    };
    buttons.emplace_back() = {
        BT_CClickButton, 11, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x0000000D, 0,
        2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, NULL, 0, 0x00000000, 0x00000000, 35
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        WID_Multiplayer, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 2
    };
    return window.get();
}

