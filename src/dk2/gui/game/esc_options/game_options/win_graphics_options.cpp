//
// Created by DiaLight on 6/22/2025.
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

dk2::WindowCfg *GameOptions_GraphicsOptions_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {  // title "Graphics Options"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 0, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000001, 96, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {  // icon with title "Gamma"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 160, 1240, 72, 0, 0, 1240, 72, 0, dk2::fun_f34_429C90, dk2::CButton_render_428A30, 0x00000000, 135, 0x000000C0, 0x00000000, 0
    };
    buttons.emplace_back() = {  // gamma slider
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x0000000F, 0x0000003C, 0,
        1460, 240, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_429CD0, dk2::CButton_render_414750, 0x00000000, 1, 0x00000006, 0x00000040, 16
    };
    buttons.emplace_back() = {  // icon with title "Water Translucency"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 160, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1444, 0x000000C1, 0x00000000, 0
    };
    buttons.emplace_back() = {  // water translucency toggle
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_429F00, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 240, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429D90, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {  // icon with title "Environment Mapping"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 320, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1450, 0x000000C3, 0x00000000, 0
    };
    buttons.emplace_back() = {  // environment mapping toggle
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42A0F0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 400, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_429F80, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {  // icon with title "Shadow Detail Level"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1280, 320, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 1445, 0x000000C2, 0x00000000, 0
    };
    buttons.emplace_back() = {  // shadow detail level slider
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000003, 0,
        1460, 400, 940, 64, 0, 0, 940, 64, 0, dk2::fun_f34_42A130, dk2::CButton_render_414750, 0x00000000, 0, 0x00000003, 0x00000000, 21
    };
    buttons.emplace_back() = {  // Continue Game
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_428710_toggleMenu, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 1100, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 142, 0x000000C7, 0x00000001, 23
    };
    buttons.emplace_back() = {  // icon with title "Graphics Options"
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        20, 480, 1240, 72, 0, 0, 1240, 72, 0, NULL, dk2::CButton_render_428A30, 0x00000000, 96, 0x000000BB, 0x00000000, 0
    };
    buttons.emplace_back() = {  // graphics options switch
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_42A330, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        160, 560, 1240, 72, 0, 0, 1080, 72, 0, NULL, dk2::CButton_render_42A160, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
    buttons.emplace_back() = {  // Back
        BT_CClickButton, 3, 0, NULL, NULL, 25, 1, 0x00000000, 0x00000000, 0,
        1280, 1100, 1240, 72, 0, 0, 1240, 96, 0, NULL, dk2::CButton_render_428A30, 0x00000002, 20, 0x000000B9, 0x00000001, 23
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_GameOptions_GraphicsOptions, 0, 0, 0, 180, 2560, 1280, 0, 0, 2560, 1280, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
