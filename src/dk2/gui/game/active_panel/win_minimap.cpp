//
// Created by DiaLight on 6/22/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../game_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *ActivePanel_Minimap_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Query Tool
            BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick_41A2B0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 124, 120, 0, 0, 80, 80, 2149, NULL, dk2::CButton_render_4129E0, 0x0000001C, 32, 0x00000000, 0x00000000, 8
    };
    buttons.emplace_back() = {  // Sell
        BT_CClickButton, 255, 0, dk2::CButton_handleLeftClick_4163F0, NULL, 0, 0, 0x00000000, 0x000000FF, 2,
        20, 0, 120, 120, 48, 0, 80, 80, 2151, NULL, dk2::CButton_render_4129E0, 0x0000001D, 33, 0x00000000, 0x00000000, 9
    };
    buttons.emplace_back() = {  // Resize Map
        BT_CClickButton, 253, 0, dk2::CButton_handleLeftClick_416480, dk2::CButton_handleRightClick_416580, 0, 0, 0x00000001, 0x000000FD, 6,
        16, 16, 128, 128, 48, 48, 80, 80, 2145, NULL, dk2::CButton_render_4129E0, 0x0000001F, 35, 0x00000000, 0x00000000, 11
    };
    buttons.emplace_back() = {  // Options
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 4,
        0, 20, 128, 128, 0, 48, 80, 80, 2147, NULL, dk2::CButton_render_4129E0, 0x0000001E, 34, 0x00000000, 0x00000000, 10
    };
    buttons.emplace_back() = {  // Map + Buttons
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_41A2D0, dk2::CButton_handleRightClick_41A7D0, 0, 0, 0x00000000, 0x00000000, 0,
        40, 0, 280, 280, 0, 44, 356, 312, 0, NULL, dk2::CButton_render_414210, 0x00000000, 0, 0x00000000, 0x00000000, 12
    },

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_MiniMap, 1, 0, 20, 1460, 460, 460, 0, 0, 460, 460, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}

