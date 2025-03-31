//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}

dk2::WindowCfg *Extras_ViewMovies_layout() {
    if (window) return window.get();

    buttons.emplace_back() = {
        BT_CTextBox, 51, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        632, 40, 1324, 144, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 8, 0x00000000, 0x00010000, 0
    };
    buttons.emplace_back() = {
        BT_CVerticalSlider, 52, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        80, 388, 48, 1180, 0, 0, 48, 1180, 0, dk2::CButton_f34_53B810, dk2::CVerticalSlider_render_551820, 0x00000000, 0, 0x00000001, 0x00000040, 27
    };
    buttons.emplace_back() = {
        BT_CClickButton, 53, 0, dk2::CButton_leftClickHandler_53B840, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        224, 388, 280, 212, 0, 0, 280, 212, 0, NULL, dk2::CButton_render_53C070, 0x00000000, 0, 0x00000001, 0x00000000, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 54, 0, dk2::CButton_leftClickHandler_53B840, NULL, 0, 0, 0x00000001, 0x00000000, 0,
        224, 628, 280, 212, 0, 0, 280, 212, 0, NULL, dk2::CButton_render_53C070, 0x00000001, 0, 0x00000002, 0x00000000, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 55, 0, dk2::CButton_leftClickHandler_53B840, NULL, 0, 0, 0x00000002, 0x00000000, 0,
        224, 868, 280, 212, 0, 0, 280, 212, 0, NULL, dk2::CButton_render_53C070, 0x00000002, 0, 0x00000003, 0x00000000, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 56, 0, dk2::CButton_leftClickHandler_53B840, NULL, 0, 0, 0x00000003, 0x00000000, 0,
        224, 1108, 280, 212, 0, 0, 280, 212, 0, NULL, dk2::CButton_render_53C070, 0x00000003, 0, 0x00000004, 0x00000000, 33
    };
    buttons.emplace_back() = {
        BT_CClickButton, 57, 0, dk2::CButton_leftClickHandler_53B840, NULL, 0, 0, 0x00000004, 0x00000000, 0,
        224, 1348, 280, 212, 0, 0, 280, 212, 0, NULL, dk2::CButton_render_53C070, 0x00000004, 0, 0x00000005, 0x00000000, 33
    };
    buttons.emplace_back() = {
        BT_CTextBox, 59, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        584, 452, 1752, 108, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53C120, 0x00000000, 6, 0x00000006, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CTextBox, 60, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        584, 692, 1752, 108, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53C120, 0x00000000, 7, 0x00000007, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CTextBox, 61, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        584, 928, 1752, 108, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53C120, 0x00000000, 8, 0x00000008, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CTextBox, 62, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        584, 1172, 1752, 108, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53C120, 0x00000000, 9, 0x00000009, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CTextBox, 63, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        584, 1416, 1752, 108, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_53C120, 0x00000000, 10, 0x0000000A, 0x00000000, 0
    };
    buttons.emplace_back() = {
        BT_CClickButton, 65, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 6, 1, 0x00000000, 0x0000003C, 0,
        2336, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x0000000B, 0x00000000, 35
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        WID_ViewMovies, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, 0x00000000, 0x00000000, 0,
        0, 0, 0, 0, 0, buttons.data(), 2
    };
    return window.get();
}

