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

dk2::WindowCfg *ActivePanel_PanelTabs_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Creatures
            BT_CClickButton, 248, 1, dk2::CButton_handleLeftClick_416C20, NULL, 0, 0, 0x000000F8, 0x00000004, 0,
            0, 0, 128, 128, 0, 0, 128, 128, 2153, dk2::fun_f34_416E20, dk2::CButton_render_412260, 0x00000004, 173, 0x00000000, 0x00000000, 4
    };
    buttons.emplace_back() = {  // Rooms
        BT_CClickButton, 251, 1, dk2::CButton_handleLeftClick_416C20, NULL, 0, 0, 0x000000FB, 0x00000001, 0,
        136, 0, 128, 128, 0, 0, 128, 128, 2155, dk2::fun_f34_416E20, dk2::CButton_render_412260, 0x00000005, 174, 0x00000000, 0x00000000, 1
    };
    buttons.emplace_back() = {  // Keeper Spells
        BT_CClickButton, 250, 1, dk2::CButton_handleLeftClick_416C20, NULL, 0, 0, 0x000000FA, 0x00000002, 0,
        272, 0, 128, 128, 0, 0, 128, 128, 2157, dk2::fun_f34_416E20, dk2::CButton_render_412260, 0x00000006, 175, 0x00000000, 0x00000000, 2
    };
    buttons.emplace_back() = {  // Workshop Items
        BT_CClickButton, 249, 1, dk2::CButton_handleLeftClick_416C20, NULL, 0, 0, 0x000000F9, 0x00000003, 0,
        408, 0, 128, 128, 0, 0, 128, 128, 2159, dk2::fun_f34_416E20, dk2::CButton_render_412260, 0x00000007, 178, 0x00000000, 0x00000000, 3
    };
    buttons.emplace_back() = {  // Resize Panel
        BT_CClickButton, 247, 1, dk2::CButton_handleLeftClick_4167D0, NULL, 0, 0, 0x000000F7, 0x00000001, 0,
        544, 0, 128, 128, 0, 0, 88, 128, 2161, NULL, dk2::CButton_render_4129E0, 0x0000002C, 0, 0x00000000, 0x00000000, 7
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_PanelTabs, 1, 0, 472, 1360, 672, 156, 0, 0, 672, 156, 0, dk2::Window_fun_f1E_418EE0, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
