//
// Created by DiaLight on 3/25/2025.
//

#include "visual_debug.h"
#include <dk2/NameAndSurf.h>
#include <dk2/NameAndSurfEx.h>
#include <dk2_functions.h>
#include <dk2_globals.h>


void dumpButtons(dk2::ButtonCfg *cur) {
    if (cur == nullptr) return;
    for (; cur->idx != 0xFFFFFFFF; ++cur) {
        printf("{");
        printf("%d", cur->kind);
        printf(", %d", cur->idx);
        printf(", %d", cur->f5);
        printf(", 0x%p", cur->leftClickHandler);
        printf(", 0x%p", cur->rightClickHandler);
        printf(", %d", cur->_nextWindowIdOnClick);
        printf(", %d", cur->f12);
        printf(", 0x%08X", cur->clickHandler_arg1);
        printf(", 0x%08X", cur->clickHandler_arg2);
        printf(", %d", cur->posFlags);
        printf(",\n%d", cur->x);
        printf(", %d", cur->y);
        printf(", %d", cur->w);
        printf(", %d", cur->h);
        printf(", %d", cur->x_offs);
        printf(", %d", cur->y_offs);
        printf(", %d", cur->width);
        printf(", %d", cur->height);
        printf(", %d", cur->f30);
        printf(", 0x%p", cur->f34);
        printf(", 0x%p", cur->renderFun);
        printf(", 0x%08X", cur->btn_arg1);
        printf(", %d", cur->textId);
        printf(", 0x%08X", cur->p_idxLow);
        printf(", 0x%08X", cur->idxHigh);
        printf(", %d", cur->nameIdx);
        printf("},\n");
    }
}

enum ButtonType {
    BT_CClickButton = 0,
    BT_CRadioButton = 1,
    BT_CVerticalSlider = 2,
    BT_CHorizontalSlider = 3,
    BT_CDragButton = 4,
    BT_CHoldButton = 5,
    BT_CCheckBoxButton = 6,
    BT_CTextBox = 7,
    BT_CTextInput = 8,
    BT_CSpinButton = 9,
    BT_CListBox = 0xA,
    BT_CProgressBar = 0xB,
    BT_CClickTextButton = 0xC,
};

enum WindowId {
    WID_Main = 1,
    WID_SinglePlayer = 2,
    WID_Multiplayer = 3,
};

namespace {
    dk2::ButtonCfg Main_Main_BtnArr[] {
        { // dungeon Keeper 2 title
            BT_CTextBox, 590, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            628, 0, 1304, 472, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5367D0, NULL, 0, 0x00000000, 0x00000000, 0
        },
        { // Warning: you are very low on a hard drive space
            BT_CTextBox, 688, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1740, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_537CA0, NULL, 0, 0x00000000, 0x00000000, 0
        },
        { // version string
            BT_CTextBox, 689, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 1740, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CTextBox_renderVersion, NULL, 0, 0x00000000, 0x00000000, 0
        },

        { // Single Player game
            BT_CClickButton, 1, 0, dk2::CButton_handleLeftClick2, NULL, 0, 0, MAKELONG(0x0001, WID_SinglePlayer), 0x00000000, 0,
            628, 492, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 71, 0x00000000, 0x00040002, 32
        },
        { // Multiplayer game
            BT_CClickButton, 2, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000001, 0x00010002, 0,
            628, 672, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 72, 00000001, 0x00040002, 32
        },
        { // My Pet Dungeon
            BT_CClickButton, 10, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000001, 0x0002000B, 0,
            628, 852, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 1675, 00000002, 0x00040002, 32
        },
        { // Options
            BT_CClickButton, 3, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000001, 0x00030005, 0,
            628, 1112, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 94, 00000003, 0x00040002, 32
        },
        { // Extras
            BT_CClickButton, 4, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000001, 0x00040006, 0,
            628, 1292, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 73, 00000004, 0x00040002, 32
        },
        { // Quit
            BT_CClickButton, 5, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000001, 0x00050008, 0,
            628, 1568, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 28, 00000005, 0x00040002, 32
        },

        {
            0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0
        },
    };

    dk2::WindowCfg Main_Main_WinCfg {
        WID_Main, 0, 0, 0, 0, 0xA00, 0x780, 0, 0, 0xA00, 0x780, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_Main_BtnArr, 1
    };

    dk2::ButtonCfg Main_SinglePlayer_BtnArr[] {
        { // Single Player Game title
            BT_CTextBox, 591, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            464, 24, 1600, 232, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, NULL, 0, 0x00000000, 0x00000000, 0
        },

        { // New Campaign
            BT_CClickButton, 6, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000002, 0x00000001, 0,
            616, 408, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 140, 0x00000000, 0x00050002, 32
        },
        { // Continue Campaign
            BT_CClickButton, 567, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000002, 0x0001000D, 0,
            616, 588, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 2059, 0x00000001, 0x00050002, 32
        },
        { // Skirmish
            BT_CClickButton, 8, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000002, 0x0002000A, 0,
            616, 852, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 141, 0x00000002, 0x00050002, 32
        },
        { // Load Game
            BT_CClickButton, 7, 0, dk2::CButton_handleLeftClick_00538000, NULL, 0, 0, 0x00000002, 0x00030007, 0,
            616, 1032, 1304, 172, 0, 0, 1304, 172, 0, NULL, dk2::CButton_render_532670, NULL, 145, 0x00000003, 0x00050002, 32
        },
        { // X (Back)
            BT_CClickButton, 9, 0, dk2::CButton_leftClick_changeMenu, NULL, 1, 1, 0x00010002, 0x00040000, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, NULL, 0, 0x00000004, 0x00000000, 36
        },

        {
            0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0
        },
    };

    dk2::WindowCfg Main_SinglePlayer_WinCfg {
        WID_SinglePlayer, 0, 0, 0, 0, 0xA00, 0x780, 0, 0, 0xA00, 0x780, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_SinglePlayer_BtnArr, 1
    };

    dk2::ButtonCfg Main_Multiplayer_BtnArr[] {
        {
            BT_CTextBox, 13, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 52, 2560, 160, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, NULL, 16, 0x00000000, 0x00010000, 0
        },
        {
            BT_CListBox, 12, 0, NULL, NULL, 0, 0, (uint32_t) dk2::getListElementCount, (uint32_t) dk2::CListBox_listfun, 0,
            0, 400, 2560, 460, 0, 0, 2560, 460, 0, dk2::CListBox_sub_530440, dk2::CListBox_sub_54EA90, (uint32_t) dk2::CVerticalSlider_render_54FF00, 0, (uint32_t) &dk2::g_listItemNum, 0x00000000, 0
        },
        {
            BT_CClickButton, 18, 0, dk2::CButton_leftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x00000016, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, NULL, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 11, 0, dk2::CButton_leftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x0000000D, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, NULL, 0, 0x00000000, 0x00000000, 35
        },

        {
            0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0
        },
    };

    dk2::WindowCfg Main_Multiplayer_WinCfg {
        WID_Multiplayer, 0, 0, 0, 0, 0xA00, 0x780, 0, 0, 0xA00, 0x780, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_Multiplayer_BtnArr, 2
    };

    dk2::WindowCfg *mainView_replaced[33] = {
        &Main_Main_WinCfg, // 1
        &Main_SinglePlayer_WinCfg, // 2
        &Main_Multiplayer_WinCfg, // 3
        // &Main_Options_WinCfg,
        // &Extras_ViewMovies_WinCfg,
        // &Main_Extras_WinCfg,
        // &Map3d_MissionBriefing,
        // &Main_LoadGame_WinCfg,
        // &Main_Scrimish_WinCfg,
        // &Multiplayer_IpxLocalNetwork,
        // &Multiplayer_TcpIpInternet_WinCfg,
        // &Options_Graphics_WinCfg,
        // &Options_Sound_WinCfg,
        // &Options_Control_WinCfg,
        // &Extras_TodaysTopKeepers_WinCfg,
        // &MissionDebriefing_Stats1_WinCfg,
        // &Net_AddressBook_WinCfg,
        // &Net_CreateLobby_WinCfg,
        // &Skirmish_MapSelect_WinCfg,
        // &Multiplayer_MapSelect_WinCfg,
        // &GameSettings_WinCfg,
        // &Map3d_WinCfg,
        // &Main_MyPetDungeon_WinCfg,
        // &Net_InternetDungeonWatch_WinCfg,
        // &Extras_Credits_WinCfg,
        // &MissionDebriefing_WinCfg,
        // &MissionDebriefing_Stats2_WinCfg,
        // &MissionDebriefing_Stats3_WinCfg,
        // &Main_Quit_WinCfg,
        // &Empty_WinCfg,
        // &CreateLobby_Nick_WinCfg,
        // &MyPetDungeon_Other_WinCfg,
        // &Main_endOfList,
    };


    dk2::ButtonCfg Game_win0_BtnArr[] {
        {
            BT_CClickButton, 1, 0, dk2::leftClickHandler_417730, NULL, 0, 0, 0x1, 0x00000001, 0,
            0, 0, 64, 440, 24, 0, 6, 440, 0, dk2::fun_f34_410A60, dk2::renderFun_4129E0, 0xA, 0, 0x00000000, 0x00000000, 14
        },
        {
            BT_CClickButton, 1, 0, dk2::leftClickHandler_417730, NULL, 0, 0, 0xFFFFFFFF, 0x00000001, 0,
            0, 0, 64, 440, 24, 0, 6, 440, 0, dk2::fun_f34_410A60, dk2::renderFun_4129E0, 0xB, 0, 0x00000000, 0x00000000, 14
        },
        {
            BT_CClickButton, 2, 0, dk2::BtnHandler_leftClickHandler_410860, dk2::BtnHandler_rightClickHandler_4118B0, 0, 0, 0x1, 0x00000000, 0,
            0, 0, 212, 128, 0, 0, 212, 128, 0, dk2::fun_f34_410990, dk2::renderFun_412FC0, 0xE, 174, 0x00000000, 0x00000000, 5
        },

        {
            0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0
        },
    };

    dk2::WindowCfg Game_win0 = {
        1, 0, 1, 0x244, 0x5D0, 0x2DC, 0x1D4, 0, 0, 0x2DC, 0x1D4, 0, 0, &dk2::CWindow_getPanelItemsCount, 0,
        0, 0, 0, 0, 0, Game_win0_BtnArr, 0
    };
}


typedef char (__cdecl *CButton_render_t)(dk2::CButton *btn, dk2::CFrontEndComponent *front);

char __cdecl dk2::CButton_render_532670(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
    // fixme: tmp usages fix
    auto orig = (CButton_render_t) 0x00532670;
    return orig(btn, front);
}

typedef char (__cdecl *CButton_render_t)(dk2::CButton *btn, dk2::CFrontEndComponent *front);

char __cdecl dk2::CButton_render_541F50(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
    // fixme: tmp usages fix
    auto orig = (CButton_render_t) 0x00541F50;
    return orig(btn, front);
}


int dk2::CFrontEndComponent::load() {
    { // patch
        mainView[0] = &::Main_Main_WinCfg;
        mainView[1] = &::Main_SinglePlayer_WinCfg;
        mainView[2] = &::Main_Multiplayer_WinCfg;


        // dumpButtons(dk2::mainView[2]->pButtonCfg_list);
        // dumpButtons(dk2::gameView[0]->pButtonCfg_list);
        // printf("var16: %d\n", gameView[0]->pButtonCfg_list[2].var16);
        // for (int i = 0; i < 16; ++i) {
        //     unsigned int v2_strId = dk2::gameView[0]->pButtonCfg_list[2].var16 + i;
        //     uint8_t *MbString = MyMbStringList_idx1091_getMbString(v2_strId);
        //     wchar_t buf[128];
        //     buf[0] = 0;
        //     MBToUni_convert(MbString, buf, 128);
        //     printf("%d: \"%S\"\n", i, buf);
        // }
        // gameView[0] = &::Game_win0;
    }


    MyResources_instance.gameCfg.useFe_playMode = 5;
    CFrontEndComponent3D_instance.CFrontEndComponent_p = this;
    MyResources_instance.gameCfg.unk_f16C = 0;
    g_petDungeonLevelIdx = 0;
    this->sub_536850();

    char Buffer[260];
    int status;

    NameAndSurf v34_frontend_arr28[] {
        {"Confirm", &this->Confirm_surf},
        {"Confirm-Over", &this->ConfirmOver_surf},
        {"Confirm-Click", &this->ConfirmClick_surf},
        {"Cancel", &this->Cancel_surf},
        {"Cancel-Over", &this->CancelOver_surf},
        {"Cancel-Click", &this->CancelClick_surf},
        {"Load_Skirmish", &this->Load_Skirmish_surf},
        {"Load_Skirmish-Over", &this->Load_Skirmish_Over_surf},
        {"Load_Skirmish-Click", &this->Load_Skirmish_Click_surf},
        {"Save", &this->Save_surf},
        {"Save-Over", &this->Save_Over_surf},
        {"Save-Click", &this->Save_Click_surf},
        {"Tick-0", &this->Tick_0_surf},
        {"Tick-1", &this->Tick_1_surf},
        {"0-H-Left_Arrow", &this->LeftArrow_0_H_surf},
        {"0-H-Scroll_Bar_BG", &this->Scroll_Bar_BG_0_H_surf},
        {"0-H-Right_Arrow", &this->Right_Arrow_0_H_surf},
        {"1-V-Up_Arrow", &this->Up_Arrow_1_V_surf},
        {"1-V-Scroll_Bar_BG", &this->Scroll_Bar_BG_1_V_surf},
        {"1-V-Down_Arrow", &this->Down_Arrow_1_V_surf},
        {"1-H-Down_Arrow", &this->Down_Arrow_1_H_surf},
        {"1-H-Scroll_Bar_BG", &this->Scroll_Bar_BG_1_H_surf},
        {"1-H-Up_Arrow", &this->Up_Arrow_1_H_surf},
        {"2-H-Scroll_Bar_BG", &this->Scroll_Bar_BG_2_H_surf},
        {"2-V-Scroll_Bar_BG", &this->Scroll_Bar_BG_2_V_surf},
        {"3-V-Scroll_Bar_BG", &this->Scroll_Bar_BG_3_V_surf},
        {"4-V-Scroll_Bar_BG", &this->Scroll_Bar_BG_4_V_surf},
        {"5-V-Scroll_Bar_BG", &this->Scroll_Bar_BG_5_V_surf},
    };
    for (auto &i : v34_frontend_arr28) {
        readSurfFromFile(
            &status, i.surf, &g_confSurfDesc,
            &MyResources_instance.frontEndFileMan, i.name, getResourceExtensionFlags());
        if (status < 0) {
            sprintf(Buffer, "Unable to load FrontEnd '%s'", i.name);
        }
    }

    this->buildGlowParts(&this->LeftArrow_0_H_surf, &this->LeftArrow_0_H_glow_atlas, this->LeftArrow_0_H_glow_parts, this->LeftArrow_0_H_glow_part_locs);
    this->LeftArrow_0_H_surf.reset();

    this->buildGlowParts(&this->Scroll_Bar_BG_0_H_surf, &this->surf17, this->surf20_x5, this->aabb3_x5);
    this->Scroll_Bar_BG_0_H_surf.reset();

    this->buildGlowParts(&this->Right_Arrow_0_H_surf, &this->surf16, this->surf19_x5, this->aabb2_x5);
    this->Right_Arrow_0_H_surf.reset();

    memset(this->UncCounters3_arr3, 0, sizeof(this->UncCounters3_arr3));

    this->buildGlowParts(&this->Up_Arrow_1_V_surf, &this->surf39, this->surf42_x5, this->aabb8_x5);
    this->Up_Arrow_1_V_surf.reset();

    this->buildGlowParts(&this->Scroll_Bar_BG_1_V_surf, &this->surf41, this->surf44_x5, this->aabb10_x5);
    this->Scroll_Bar_BG_1_V_surf.reset();

    this->buildGlowParts(&this->Down_Arrow_1_V_surf, &this->surf40, this->surf43_x5, this->aabb9_x5);
    this->Down_Arrow_1_V_surf.reset();

    this->buildGlowParts(&this->Down_Arrow_1_H_surf, &this->surf25, this->surf28_x5, this->aabb4_x5);
    this->Down_Arrow_1_H_surf.reset();

    this->buildGlowParts(&this->Scroll_Bar_BG_1_H_surf, &this->surf27, this->surf30_x5, this->aabb6_x5);
    this->Scroll_Bar_BG_1_H_surf.reset();

    this->buildGlowParts(&this->Up_Arrow_1_H_surf, &this->surf26, this->surf29_x5, this->aabb5_x5);
    this->Up_Arrow_1_H_surf.reset();

    memset(this->UncCounters3_arr1, 0, sizeof(this->UncCounters3_arr1));
    this->buildGlowParts(&this->Scroll_Bar_BG_2_H_surf, &this->surf33, this->surf34_x5, this->aabb7_x5);
    this->Scroll_Bar_BG_2_H_surf.reset();

    memset(this->UncCounters3_arr2, 0, sizeof(this->UncCounters3_arr2));
    this->buildGlowParts(&this->Scroll_Bar_BG_2_V_surf, &this->surf47, this->surf48_x5, this->aabb11_x5);
    this->Scroll_Bar_BG_2_V_surf.reset();

    memset(this->UncCounters3_arr5, 0, sizeof(this->UncCounters3_arr5));
    this->buildGlowParts(&this->Scroll_Bar_BG_3_V_surf, &this->surf56, this->surf57_x5, this->aabb14_x5);
    this->Scroll_Bar_BG_3_V_surf.reset();

    memset(this->UncCounters3_arr8, 0, sizeof(this->UncCounters3_arr8));
    this->buildGlowParts(&this->Scroll_Bar_BG_4_V_surf, &this->surf50, this->surf51_x5, this->aabb12_x5);
    this->Scroll_Bar_BG_4_V_surf.reset();

    this->buildGlowParts(&this->Scroll_Bar_BG_5_V_surf, &this->surf53, this->surf54_x5, this->aabb13_x5);
    this->Scroll_Bar_BG_5_V_surf.reset();


    NameAndSurf tickToggles[] {
        {"Tick_Toggle-0", &this->Tick_Toggle_0_surf},
        {"Tick_Toggle-0-Over", &this->Tick_Toggle_0_Over_surf},
        {"Tick_Toggle-0-Click", &this->Tick_Toggle_0_Click_surf},
        {"Tick_Toggle-1", &this->Tick_Toggle_1_surf},
        {"Tick_Toggle-1-Over", &this->Tick_Toggle_1_Over_surf},
        {"Tick_Toggle-1-Click", &this->Tick_Toggle_1_Click_surf},
    };
    for (auto &i : tickToggles) {
        readSurfFromFile(&status, i.surf, NULL,
                         &MyResources_instance.frontEndFileMan, i.name, getResourceExtensionFlags());
        if (status < 0) {
            sprintf(Buffer, "Unable to load FrontEnd '%s'", i.name);
        }
    }


    NameAndSurfEx scrollBars[] {
        {"0-H-Scroll_Bar", &this->Scroll_Bar_0_H_surfEx},
        {"Cursor\\C-Pointer", &this->Cursor_C_Pointer_surfEx},
        {"Cursor\\C-Pointer-2", &this->Cursor_C_Pointer_2_surfEx},
        {"1-V-Scroll_Bar", &this->Scroll_Bar_1_V_surfEx},
        {"0-V-Scroll_Bar", &this->Scroll_Bar_0_V_surfEx},
        {"1-H-Scroll_Bar", &this->Scroll_Bar_1_H_surfEx},
        {"2-H-Scroll_Bar", &this->Scroll_Bar_2_H_surfEx},
        {"2-V-Scroll_Bar", &this->Scroll_Bar_2_V_surfEx},
    };
    for (auto &i : scrollBars) {
        loadArtToSurfaceEx(&status, i.surfEx,
                           &MyResources_instance.frontEndFileMan, (char*) i.name, getResourceExtensionFlags());
        if (status < 0) {
            sprintf(Buffer, "Unable to load FrontEnd '%s'", i.name);
        }
    }

    if (MyResources_instance.playerCfg.kbLayoutId == 17) {
        readSurfFromFile(
            &status, &this->Logo_surf, &g_confSurfDesc,
            &MyResources_instance.frontEndFileMan, "Logo-Japanese", getResourceExtensionFlags());
    } else {
        readSurfFromFile(
            &status, &this->Logo_surf, &g_confSurfDesc,
            &MyResources_instance.frontEndFileMan, "Logo", getResourceExtensionFlags());
    }

    memset(g_bgTiles_surf, 0, sizeof(g_bgTiles_surf));
    memset(g_bgTiles_loaded, 0, sizeof(g_bgTiles_loaded));

    for (int i = 0; i < 24; ++i) {
        MySurface *bgTiles_surf_pos = &g_bgTiles_surf[i];
        MyBgTile *bgTile_name_pos = &g_bgTiles[i];
        if (g_bgTiles_loaded[i]) continue;
        sprintf(Buffer, "%s%s", "BG_Tiles\\BG-", bgTile_name_pos->name);
        readSurfFromFile(&status, bgTiles_surf_pos, &g_confSurfDesc,
                         &MyResources_instance.frontEndFileMan, Buffer, getResourceExtensionFlags());
        if (status < 0) {
            continue;
        }
        g_bgTiles_loaded[i] = 1;
    }

    this->f58EC = 1;
    this->f5940 = 1;


    memset(g_bg2d_surface, 0, sizeof(g_bg2d_surface));
    memset(g_bg2d_loaded, 0, sizeof(g_bg2d_loaded));

    if (MyResources_instance.gameCfg.useFe2d_unk1) {
        readSurfFromFile(&status, &this->f30F3, NULL,
                         &MyResources_instance.frontEndFileMan, "2d-bg\\map_template", getResourceExtensionFlags());
        if (MyResources_instance.gameCfg.useFe2d_unk1) {
            for (int i = 1; i < 11; ++i) {
                MyDdSurfaceEx *v19_surfacePos = &g_bg2d_surface[i];
                MyIdxMapName *v20_namePos = &g_bg2d[i];
                if (g_bg2d_loaded[i]) continue;
                sprintf(Buffer, "%s%s", "2D-BG\\", v20_namePos->name);
                loadArtToSurfaceEx(
                    &status, v19_surfacePos,
                    &MyResources_instance.frontEndFileMan, Buffer, getResourceExtensionFlags());
                if (status < 0) {
                    continue;
                }
                g_bg2d_loaded[i] = 1;
            }
        }
        for (int i = 0; i < 116; ++i) {
            StubStruc6B84C8 *v22_bg2d2_pos = &g_bgLevel2d[i];
            MyDdSurfaceEx *p_surfPos = &this->bgLevel2d[i];

            memset(Buffer, 0, sizeof(Buffer));
            sprintf(Buffer, "%s%s", "2D-BG\\", v22_bg2d2_pos->name);
            loadArtToSurfaceEx(
                &status, p_surfPos,
                &MyResources_instance.frontEndFileMan, Buffer, getResourceExtensionFlags());
            if (status < 0)
                break;
            *(DWORD*) &p_surfPos->dd_surf.fld10_00 = 0xFFFF00FF;
            p_surfPos->dd_surf.dwColorSpaceValue_00 = 0;
        }
    }

    this->cgui_manager.createElements(mainView, (CDefaultPlayerInterface*) this);
    g_FontObj3_instance.setFontMask(&status, (PixelMask*) &this->fontMask_3031E);
    this->sub_54CC70();
    this->sub_54CB50();
    this->sub_54CDE0();
    this->sub_546F00();
    this->sub_547EE0();
    this->sub_5472F0();
    this->bakeButton(1, 4u, 6);
    this->bakeButton(2, 5u, 6);
    this->bakeButton(4, 6u, 6);
    this->bakeButton(6, 7u, 6);
    this->bakeButton(11, 0xAu, 5);
    this->bakeButton(10, 0xBu, 5);
    this->bakeButton(39, 0xCu, 5);
    this->f6705 = 1;
    this->f6706 = 1;
    this->f6707 = 1;
    this->f6708 = 1;
    this->f670B = 1;
    this->f670C = 1;
    this->f670D = 1;
    this->sub_536A80();
    g_sceneObjectIdx = 0;
    this->fontMask_3031E = this->fontMask_3031E;
    this->f5FF8 = this->f30322;
    this->sub_54FCF0(696, 48);
    this->sub_54FCF0(72, 8);
    this->sub_54FCF0(150, 17);
    this->sub_54FCF0(469, 33);
    this->sub_54FCF0(477, 34);
    this->sub_54FCF0(580, 39);
    this->sub_54FCF0(220, 11);
    this->sub_54FCF0(203, 10);
    this->sub_54CE30(150, 17);
    this->sub_54FCF0(180, 26);
    this->sub_54FCF0(185, 27);
    this->sub_54FCF0(195, 45);
    this->sub_552420(17, 150, 0, 0, 12, 113);
    this->sub_552420(26, 180, 0, 0, 12, 113);
    this->sub_552420(27, 185, 0, 0, 12, 113);
    this->sub_552420(45, 195, 0, 0, 12, 113);
    this->sub_552420(48, 696, 0, 0, 12, 170);
    this->sub_552420(33, 469, 0, 0, 12, 170);
    this->sub_552420(34, 477, 0, 0, 12, 170);
    this->sub_552420(39, 580, 0, 0, 12, 170);
    this->sub_552420(11, 220, 0, 0, 12, 170);
    this->sub_552420(10, 203, 0, 0, 12, 170);
    int result = this->sub_552420(8, 72, 0, 0, 12, 225);
    this->mp_isHost = 0;
    return result;
}

void __cdecl dk2::changeGui(int a1_isCurrent, int a2_windowId, CFrontEndComponent *a3) {
    CFrontEndComponent *v3 = a3;
    CWindow *window = a3->cgui_manager.findGameWindowById(a2_windowId);
    if (!window) return;
    if (!a1_isCurrent || !MyResources_instance.gameCfg.useFe2d_unk1) {
        g_button73ED9C = 0;
        window->f44_isCurrent = a1_isCurrent;
        return;
    }
    int f6A_ddSurfIdx_eos = (unsigned __int16) window->f6A_ddSurfIdx_eos;
    if ((unsigned __int16) f6A_ddSurfIdx_eos == 4) {
        switch ((unsigned __int8) MyResources_instance.playerCfg.fun_561920()) {
        case 2u: f6A_ddSurfIdx_eos = 5;
            break;
        case 3u: f6A_ddSurfIdx_eos = 6;
            break;
        case 4u: f6A_ddSurfIdx_eos = 7;
            break;
        case 5u: f6A_ddSurfIdx_eos = 8;
            break;
        case 6u: f6A_ddSurfIdx_eos = 9;
            break;
        case 7u: f6A_ddSurfIdx_eos = 10;
            break;
        default: break;
        }
    }
    int v6 = g_bg2d_loaded[f6A_ddSurfIdx_eos];
    g_surfIdx_6AD608 = f6A_ddSurfIdx_eos;
    if (v6) {
        static_MyDdSurfaceEx_BltWait(
            &a2_windowId,
            v3->pMyDdSurfaceEx, 0, 0,
            &g_bg2d_surface[f6A_ddSurfIdx_eos], 0, 0
        );
    }
    g_button73ED9C = 0;
    window->f44_isCurrent = a1_isCurrent;
}
