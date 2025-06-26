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

dk2::WindowCfg *ActivePanel_NotificationMessage_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_424790, NULL, 0, 1, 0x00000000, 0x00000000, 4,
        88, 20, 88, 88, 0, 0, 88, 88, 0, dk2::fun_f34_4246B0, dk2::CButton_render_4129E0, 0x0000008E, 1, 0x00000000, 0x00000000, 24
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, NULL, NULL, 0, 1, 0x00000000, 0x00000000, 4,
        264, 20, 88, 88, 0, 0, 88, 88, 0, dk2::fun_f34_4246B0, dk2::CButton_render_4129E0, 0x000000A7, 1, 0x00000000, 0x00000000, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_424710, NULL, 0, 1, 0x00000000, 0x00000000, 4,
        88, 20, 88, 88, 0, 0, 88, 88, 0, dk2::fun_f34_4246E0, dk2::CButton_render_4129E0, 0x000000A7, 1, 0x00000000, 0x00000000, 23
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_424720, NULL, 0, 0, 0x00000000, 0x00000000, 4,
        440, 20, 88, 88, 0, 0, 88, 88, 0, dk2::fun_f34_424660, dk2::CButton_render_4129E0, 0x00000085, 1, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CTextBox, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 20, 1096, 288, 0, 0, 1096, 288, 0, NULL, dk2::CButton_render_4242F0, (uint32_t) dk2::CListBox_renderArg1_414400, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_NotificationMessage, 0, 0, 1020, 200, 1200, 440, 0, 0, 1200, 440, 0, dk2::CWindow_sub_417EA0, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
