//
// Created by DiaLight on 4/1/2025.
//

#include <dk2_functions.h>
#include <dk2_globals.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2/utils/Area4s.h>
#include <patches/gui/main/single_player/win_custom_campaign.h>

#include "main_layout.h"

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;
}


namespace {

    inline dk2::ButtonCfg clickMainButtonCfg(
        uint32_t idx,
        uint32_t clickHandler_arg2,
        int16_t curY,
        uint32_t textId,
        uint16_t btnIdx
    ) {
        uint16_t curWindowId = MWID_SinglePlayer;
        uint16_t nextWindowId = 0;  // none
        uint16_t p_idxLowHigh = 0;
        uint16_t x16Idx = 5;
        uint16_t alignTy = 2;
        return {
            .kind=BT_CClickButton, .idx=idx, .f5=0,
            .leftClickHandler=dk2::CButton_handleLeftClick_538000, .rightClickHandler=NULL,
            ._nextWindowIdOnClick=0, .f12=0,
            .clickHandler_arg1=(uint32_t) MAKELONG(curWindowId, nextWindowId),
            .clickHandler_arg2=clickHandler_arg2,
            .posFlags=0,
            .x=616, .y=curY, .w=1304, .h=172,
            .x_offs=0, .y_offs=0, .width=1304, .height=172,
            .f30=0, .tickFun=NULL, .renderFun=dk2::CClickButton_render_532670,
            .btn_arg1=NULL, .textId=textId,
            .p_idxLow=(uint32_t) MAKELONG(btnIdx, p_idxLowHigh),
            .idxHigh=(uint32_t) MAKELONG(alignTy, x16Idx), .nameIdx=32
        };
    }


}


dk2::WindowCfg *Main_SinglePlayer_layout() {
    if (window) return window.get();

    int16_t curY = 24;
    buttons.emplace_back() = { // Single Player Game title
        BT_CTextBox, 591, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        464, curY, 1600, 232, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, NULL, 0, 0x00000000, 0x00000000, 0
    };

    curY += 24 + 180 + 180;
    buttons.emplace_back() = clickMainButtonCfg(6, 0x00000001, curY, 140, 0); // New Campaign
    curY += 180;
    buttons.emplace_back() = clickMainButtonCfg(567, 0x0001000D, curY, 2059, 1); // Continue Campaign
    curY += 180 + 84;
    buttons.emplace_back() = clickMainButtonCfg(8, 0x0002000A, curY, 141, 2); // Skirmish
    curY += 180;
    buttons.emplace_back() = clickMainButtonCfg(7, 0x00030007, curY, 145, 3); // Load Game

    if (patch::custom_campaign::enabled) {
        curY += 180 + 84;
        buttons.emplace_back() = patch::custom_campaign::SinglePlayer_CustomCampaign_btn(
            dk2::Area4s { 616, curY, 1304, 172 },
            dk2::Area4s { 0, 0, 1304, 172 }
        );
    }

    buttons.emplace_back() = { // X (Back)
        BT_CClickButton, 9, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 1, 1, 0x00010002, 0x00040000, 0,
        2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, NULL, 0, 0x00000004, 0x00000000, 36
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        MWID_SinglePlayer, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 1
    };
    return window.get();
}

