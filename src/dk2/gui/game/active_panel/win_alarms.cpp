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

dk2::WindowCfg *ActivePanel_Alarms_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // Zoom to Fight
        BT_CClickButton, 1, 0, NULL, dk2::CButton_handleRightClick_426960, 0, 0, 0x00000001, 0x00000000, 0,
        0, 0, 128, 128, 0, 0, 128, 128, 2165, dk2::fun_f34_4269D0, dk2::CButton_render_4129E0, 0x000000E1, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // Call To Arms
        BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_4268A0, dk2::CButton_handleRightClick_426830, 0, 0, 0x00000001, 0x00000000, 0,
        136, 0, 128, 128, 0, 0, 128, 128, 0, dk2::fun_f34_426920, dk2::CButton_render_4129E0, 0x000000DF, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {  // ?? Trap
        BT_CClickButton, 3, 0, NULL, dk2::CButton_handleRightClick_426A00, 0, 0, 0x00000001, 0x00000000, 0,
        264, 0, 128, 128, 0, 0, 128, 128, 0, dk2::fun_f34_426B90, dk2::CButton_render_4129E0, 0x000000DB, 0, 0x00000000, 0x00000000, 14
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_ActivePanel_Alarms, 1, 0, 2080, 1472, 480, 140, 0, 0, 480, 140, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
