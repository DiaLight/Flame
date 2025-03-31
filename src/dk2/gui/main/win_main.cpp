//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
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

dk2::WindowCfg *Main_Main_layout() {
    if (window) return window.get();
    buttons.emplace_back() = {   // dungeon Keeper 2 title
        BT_CTextBox, 590, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        628, 0, 1304, 472, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5367D0, NULL, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = { // Warning: you are very low on a hard drive space
        BT_CTextBox, 688, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 1740, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_537CA0, NULL, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = { // version string
        BT_CTextBox, 689, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 1740, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderVersion, NULL, 0, 0x00000000, 0x00000000, 0
    };

    buttons.emplace_back() = { // Single Player game
        BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_5394E0, NULL, 0, 0, MAKELONG(0x0001, WID_SinglePlayer), 0x00000000, 0,
        628, 492, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 71, 0x00000000, 0x00040002, 32
    };
    buttons.emplace_back() = { // Multiplayer game
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000001, 0x00010002, 0,
        628, 672, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 72, 00000001, 0x00040002, 32
    };
    buttons.emplace_back() = { // My Pet Dungeon
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000001, 0x0002000B, 0,
        628, 852, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 1675, 00000002, 0x00040002, 32
    };
    buttons.emplace_back() = { // Options
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000001, 0x00030005, 0,
        628, 1112, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 94, 00000003, 0x00040002, 32
    };
    buttons.emplace_back() = { // Extras
        BT_CClickButton, 4, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000001, 0x00040006, 0,
        628, 1292, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 73, 00000004, 0x00040002, 32
    };
    buttons.emplace_back() = { // Quit
        BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_538000, NULL, 0, 0, 0x00000001, 0x00050008, 0,
        628, 1568, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 28, 00000005, 0x00040002, 32
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        WID_Main, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 1
    };
    return window.get();
}

