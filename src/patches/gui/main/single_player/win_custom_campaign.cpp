//
// Created by DiaLight on 6/2/2025.
//

#include "win_custom_campaign.h"

#include <dk2/button/CButton.h>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include <dk2/gui/main/main_layout.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <memory>
#include <vector>
#include <patches/gui/button_id.h>

bool patch::custom_campaign::enabled = false;

namespace {
    std::vector<dk2::ButtonCfg> buttons;
    std::unique_ptr<dk2::WindowCfg> window;

    int __cdecl CustomCampaign_backBtn_handleLeftClick(uint32_t idx, int command, dk2::CFrontEndComponent *comp) {
        // inspired by /*005306F0*/ int __cdecl CButton_handleLeftClick_changeMenu(uint32_t, int, CFrontEndComponent *);

        dk2::g_mouseAct_bool73EDA0 = 0;
        dk2::g_button73ED9C = 0;

        // case 24:
        comp->f30C1E = 0;
        {  // CFrontEndComponent_static_539490
            dk2::MyResources_instance.gameCfg.useFe2d_unk1;
            if ( !dk2::MyResources_instance.gameCfg.useFe2d_unk1 ) {
                dk2::CCamera *cam = comp->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x110u, 2u, 0xCu, 1);
            }
            dk2::g_maybeGuiIsShowing = 0;
            dk2::g_pathAnimationEndSwitch = 29;
        }

        int result = dk2::WeaNetR_instance.updatePlayers_isHost();
        comp->mp_isHost = result;
        dk2::g_listItemNum = 0;
        return result;
    }

}

dk2::WindowCfg *patch::custom_campaign::SinglePlayer_CustomCampaign_layout() {
    if (window) return window.get();

    int16_t curY = 24;

    buttons.emplace_back() = {  // title: "Yes"
        BT_CTextBox, 562, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        0, 44, 2560, 140, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTitle_536700, 0x00000000, 20, 0x00000000, 0x00010000, 0
    };

    buttons.emplace_back() = {  // table background
        BT_CTextBox, 231, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        620, 616, 1240, 640, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderTableBackground_541980, 0x00000000, 0, 0x00000000, 0x00000000, 0
    };
    buttons.emplace_back() = {  // table header: "Map Name"
        BT_CTextBox, 470, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        640, 464, 640, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1544, 0x00000002, 0x00010001, 0
    };
    buttons.emplace_back() = {  // table header: "Size"
        BT_CTextBox, 472, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
        1540, 464, 380, 96, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 1545, 0x00000004, 0x00010000, 0
    };

    buttons.emplace_back() = {  // table body
        BT_CListBox, 696, 0, dk2::CButton_handleLeftClick_5417F0, NULL, 0, 0, (uint32_t) dk2::CListBox__540B70, (uint32_t) dk2::CListBox__get_wstr19, 0,
        640, 552, 1240, 608, 0, 0, 1240, 608, 0, dk2::CListBox_sub_530440, dk2::CButton_render_542110, (uint32_t) dk2::CVerticalSlider_render_551490, 75, (uint32_t) &dk2::g_idxLow_740348, 0x00000040, 0
    };

    buttons.emplace_back() = { // X (Back)
        BT_CClickButton, dk2::BID_CustomCampaign_Back, 0, CustomCampaign_backBtn_handleLeftClick, NULL, 0, 1, 0x00000000, 0x00000018, 0,
        2120, 1688, 192, 192, 1, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000001, 0x00000000, 36
    };
    buttons.emplace_back() = { // Y (Apply)
        BT_CClickButton, dk2::BID_CustomCampaign_Apply, 0, CustomCampaign_backBtn_handleLeftClick, NULL, 0, 1, 0x00000000, 0x0000005F, 0,
        2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
    };

    buttons.emplace_back() = EngOfButtonList;

    window = std::make_unique<dk2::WindowCfg>();
    *window = {
        MWID_SinglePlayer_CustomCampaign, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, buttons.data(), 4
    };
    return window.get();
}

