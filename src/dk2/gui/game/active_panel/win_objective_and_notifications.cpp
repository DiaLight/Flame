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

dk2::WindowCfg *ActivePanel_ObjectiveAndNotifications_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_4288C0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 0, 88, 128, 0, 0, 88, 128, 2163, NULL, dk2::CButton_render_4129E0, 0x0000008B, 1, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_4247F0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        88, 0, 88, 128, 0, 0, 88, 128, 262, dk2::fun_f34_424810, dk2::CButton_render_4129E0, 0x00000099, 1, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000000, 0x00000000, 0,
        176, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 1, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000001, 0x00000000, 0,
        264, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 2, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000002, 0x00000000, 0,
        352, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 3, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 4, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000003, 0x00000000, 0,
        440, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 4, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000004, 0x00000000, 0,
        528, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 5, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 6, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000005, 0x00000000, 0,
        616, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 6, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 7, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000006, 0x00000000, 0,
        704, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 7, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 8, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000007, 0x00000000, 0,
        792, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 8, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 9, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000008, 0x00000000, 0,
        880, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 9, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x00000009, 0x00000000, 0,
        968, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 11, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000A, 0x00000000, 0,
        1056, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 11, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 12, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000B, 0x00000000, 0,
        1144, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 12, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 13, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000C, 0x00000000, 0,
        1232, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 13, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 14, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000D, 0x00000000, 0,
        1320, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 14, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 15, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000E, 0x00000000, 0,
        1408, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 15, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 16, 0, dk2::CButton_handleLeftClick_423F50, dk2::CButton_handleRightClick_424220, 0, 0, 0x0000000F, 0x00000000, 0,
        1496, 0, 88, 128, 0, 0, 88, 128, 0, NULL, dk2::CButton_render_4129E0, 0x0000007F, 16, 0x00000000, 0x00000000, 14
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_ObjectiveAndNotifications, 1, 0, 1112, 1460, 948, 156, 0, 0, 948, 156, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
