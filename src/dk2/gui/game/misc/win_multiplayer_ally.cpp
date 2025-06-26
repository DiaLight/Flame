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

dk2::WindowCfg *Misc_MultiplayerAlly_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CClickButton, 1, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        40, 0, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000001, 58, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 2, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        860, 0, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 262, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1200, 0, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 1567, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1600, 0, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 2907, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        80, 580, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 1568, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        760, 580, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 1613, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_425AB0, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        40, 120, 600, 80, 0, 0, 600, 80, 0, dk2::fun_f34_4255F0, dk2::CButton_render_4250F0, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425B50, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        800, 120, 2160, 80, 0, 0, 200, 80, 0, NULL, dk2::CButton_render_4256B0, 0x00000095, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425D40, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        1280, 140, 120, 120, 0, 0, 120, 120, 0, NULL, dk2::CButton_render_425DF0, 0x0000010E, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        1600, 140, 480, 120, 0, 0, 480, 120, 0, NULL, dk2::CButton_render_4260F0, 0x0000010D, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_425AB0, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        40, 220, 600, 80, 0, 0, 600, 80, 0, dk2::fun_f34_4255F0, dk2::CButton_render_4250F0, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425B50, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        800, 220, 200, 80, 0, 0, 200, 80, 0, NULL, dk2::CButton_render_4256B0, 0x00000095, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425D40, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        1280, 240, 120, 120, 0, 0, 120, 120, 0, NULL, dk2::CButton_render_425DF0, 0x0000010E, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, NULL, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        1600, 240, 480, 120, 0, 0, 480, 120, 0, NULL, dk2::CButton_render_4260F0, 0x0000010D, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_425AB0, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        40, 320, 600, 80, 0, 0, 600, 80, 0, dk2::fun_f34_4255F0, dk2::CButton_render_4250F0, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425B50, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        800, 320, 200, 80, 0, 0, 200, 80, 0, NULL, dk2::CButton_render_4256B0, 0x00000095, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425D40, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        1280, 340, 120, 120, 0, 0, 120, 120, 0, NULL, dk2::CButton_render_425DF0, 0x0000010E, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, NULL, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        1600, 340, 480, 120, 0, 0, 480, 120, 0, NULL, dk2::CButton_render_4260F0, 0x0000010D, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_425AB0, NULL, 0, 0, 0x00000004, 0x00000000, 0,
        40, 420, 600, 80, 0, 0, 600, 80, 0, dk2::fun_f34_4255F0, dk2::CButton_render_4250F0, 0x00000000, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425B50, NULL, 0, 0, 0x00000004, 0x00000000, 0,
        800, 420, 200, 80, 0, 0, 200, 80, 0, NULL, dk2::CButton_render_4256B0, 0x00000095, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425D40, NULL, 0, 0, 0x00000004, 0x00000000, 0,
        1280, 440, 120, 120, 0, 0, 120, 120, 0, NULL, dk2::CButton_render_425DF0, 0x0000010E, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, NULL, NULL, 0, 0, 0x00000004, 0x00000000, 0,
        1600, 440, 480, 120, 0, 0, 480, 120, 0, NULL, dk2::CButton_render_4260F0, 0x0000010D, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_426680, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        40, 660, 256, 128, 0, 0, 256, 128, 1569, dk2::fun_f34_426650, dk2::CButton_render_4129E0, 0x00000092, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        760, 768, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 262, 0x00000000, 0x00000001, 14
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000064, 0,
        470, 700, 800, 64, 0, 0, 800, 64, 0, NULL, dk2::CButton_render_414750, 0x00000000, 1, 0x00000064, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_426730, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        40, 820, 256, 128, 0, 0, 256, 128, 1570, dk2::fun_f34_426650, dk2::CButton_render_4129E0, 0x00000093, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 3, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        760, 928, 40, 40, 0, 0, 40, 40, 0, NULL, dk2::CButton_render_4250F0, 0x00000000, 262, 0x00000000, 0x00000002, 14
    };
    buttons.emplace_back() = {
        BT_CHorizontalSlider, 3, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000064, 0,
        470, 860, 800, 64, 0, 0, 800, 64, 0, NULL, dk2::CButton_render_414750, 0x00000000, 1, 0x00000064, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_4267D0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        40, 980, 256, 128, 0, 0, 256, 128, 1571, dk2::fun_f34_426650, dk2::CButton_render_4129E0, 0x00000094, 0, 0x00000000, 0x00000000, 14
    };
    buttons.emplace_back() = {
        BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_425070, NULL, 0, 0, 0x00000000, 0x00000000, 6,
        88, 20, 88, 88, 0, 0, 88, 88, 0, NULL, dk2::CButton_render_4129A0, 0x0000008E, 0, 0x00000000, 0x00000000, 14
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        GWID_Multiplayer_Ally, 0, 0, 280, 240, 2080, 1120, 0, 0, 2080, 1120, 0, NULL, NULL, 9,
        0, 0, 0, 0, 0, buttons.data(), 0
    };
    return window.get();
}
