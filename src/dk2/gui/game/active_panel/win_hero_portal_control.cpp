//
// Created by DiaLight on 6/24/2025.
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

dk2::WindowCfg *ActivePanel_HeroPortalControl_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Zoom to Hero ToolBox
        BT_CClickButton, 245, 0, dk2::CButton_handleLeftClick_426C10, dk2::CButton_handleLeftClick_426C10, 0, 0, 0x00000000, 0x00000000, 0,
        12, 12, 256, 128, 0, 0, 256, 128, 1644, NULL, dk2::CButton_render_4129E0, 0x000000AC, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Trigger single Hero invasion
        BT_CClickButton, 244, 0, dk2::CButton_handleLeftClick_426CA0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        12, 148, 128, 128, 0, 0, 128, 128, 1645, NULL, dk2::CButton_render_4129E0, 0x000000AB, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Trigger continual Hero invasion
        BT_CClickButton, 241, 0, dk2::CButton_handleLeftClick_426CA0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        148, 148, 128, 128, 0, 0, 128, 128, 2130, NULL, dk2::CButton_render_4129E0, 0x000000AA, 0, 0x00000000, 0x00000000, 14
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_HeroPortalControl, 1, 0, 2272, 1600, 288, 432, 0, 0, 288, 432, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
