//
// Created by DiaLight on 3/25/2025.
//

#include <dk2/MyMapInfo.h>
#include <dk2/NameAndSurf.h>
#include <dk2/NameAndSurfEx.h>
#include <dk2/button/CButton.h>
#include <dk2/button/button_types.h>
#include <dk2/gui/main/main_layout.h>
#include <dk2/sound/TbSysCommand_Process.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <patches/auto_network.h>
#include <patches/gui/main/single_player/win_custom_campaign.h>
#include "visual_debug.h"


typedef char (__cdecl *CButton_render_t)(dk2::CButton *btn, dk2::CFrontEndComponent *front);

// char __cdecl dk2::CClickButton_render_532670(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
//     // fixme: tmp usages fix
//     auto orig = (CButton_render_t) 0x00532670;
//     return orig(btn, front);
// }

typedef char (__cdecl *CButton_render_t)(dk2::CButton *btn, dk2::CFrontEndComponent *front);

char __cdecl dk2::CButton_render_541F50(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
    // fixme: tmp usages fix
    auto orig = (CButton_render_t) 0x00541F50;
    return orig(btn, front);
}


int dk2::CFrontEndComponent::load() {
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

    // this->cgui_manager.createElements(mainView, (CDefaultPlayerInterface*) this);  // original
    this->cgui_manager.createElements(main_layout(), (CDefaultPlayerInterface*) this);  // dynamic layout build

    g_FontObj3_instance.setFontMask(&status, &this->fontMask_3031E);
    this->renderButtonsText_15_0_4();
    this->renderButtonsText_16_1_4();
    this->renderButtonsText_17_2_5();
    this->renderButtonsText_9_9_4();
    this->renderButtonsText_32_3_4();
    this->renderButtonsText_35_14_3__35_15_2();
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
    this->fontMask_5FF4 = this->fontMask_3031E;
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





void __cdecl dk2::CButton_handleLeftClick_538000(int a1_arg1, int a2_arg2,CFrontEndComponent *a3_frontend) {
    int v3_curWindowId = LOWORD(a1_arg1);
    int v5_nextWindowId = HIWORD(a1_arg1);
    int switchKey = LOWORD(a2_arg2);
    int btnIdx = HIWORD(a2_arg2);

    if (MyResources_instance.gameCfg.useFe2d_unk1 &&g_bg2d_loaded[g_surfIdx_6AD608] ) {
        static_MyDdSurfaceEx_BltWait(
           &a2_arg2, a3_frontend->pMyDdSurfaceEx, 0, 0,
           &g_bg2d_surface[g_surfIdx_6AD608], NULL, 0
        );
    }
    if ( btnIdx == 255 || a3_frontend->arr_x16x30_hovered[windowId_to_x16Idx(v3_curWindowId)][btnIdx] ) {
        if ( v3_curWindowId ) {
            changeGui(0, v3_curWindowId, a3_frontend);
            if ( (uint16_t) v5_nextWindowId )
                changeGui(1, (unsigned __int16)v5_nextWindowId, a3_frontend);
        }
        memset(a3_frontend->arr_x16x30_hovered, 0, sizeof(a3_frontend->arr_x16x30_hovered));
        switch ( switchKey ) {
        case 1:  // New Campaign
            if (MyResources_instance.playerCfg.getPlayerLevelStatus(1u) != 2 ||
                MyResources_instance.playerCfg.loadLevelAttempts(1u)) {
                a3_frontend->sub_537990();
            } else {
                CButton_handleLeftClick_changeMenu(0, 109, a3_frontend);
            }
            break;
        case 2:  // Multiplayer game
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x10Fu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 5;
            break;
        case 5:  // Options
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x100u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 8;
            break;
        case 6:  // Extras
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x103u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 25;
            break;
        case 7: {  // Load Game
            DirFileList_instance2_saves_sav.collectFiles(MyResources_instance.savesDir, "*.sav", 1);
            CButton *BtnBySomeId = a3_frontend->findBtnBySomeId(73, 8);
            if (BtnBySomeId)
                BtnBySomeId->f5D_isVisible = static_DirFileList_instance2_saves_sav_getCount() > 0;
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x10Fu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 6;
        } break;
        case 8:  // Quit
            a3_frontend->fun_536BA0(28, 15, 0, 111, 112, 3, NULL, 0, 0);
            break;
        case 10:  // Skirmish
            a3_frontend->playerIdx11 = 0;
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x10Fu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 26;
            break;
        case 11:  // My Pet Dungeon
            memset(a3_frontend->wstr19, 0, 0x208u);
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x106u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 16;
            break;
        case 12:  // Extras->Credits
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x109u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 17;
            break;
        case 13:  // Continue Campaign
            CFrontEndComponent_sub_538B90(0, a3_frontend);
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0xFBu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 2;
            break;
        case 15:  // Main_Options.Apply
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x101u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 28;
            break;
        case 16:  // Main_Extras.Apply
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = a3_frontend->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x104u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 28;
            break;
        default:
            return;
        }
    }
}

namespace dk2 {

    void execSwitch(CFrontEndComponent *front) {
        switch (g_pathAnimationEndSwitch) {
        case 1:
            if ( !MyResources_instance.gameCfg.useFe2d_unk1 ) {
                CCamera *cam = front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0xFAu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 12;
            break;
        case 2:  // Continue Campaign
        case 19:
            CFrontEndComponent_sub_538D00(front);
            break;
        case 3:
            CFrontEndComponent_sub_53C3C0(4, front);
            break;
        case 4:
            CFrontEndComponent_sub_53A010(0, front);
            break;
        case 5:  // Multiplayer game
            do_smth_and_execute_action_8(front);
            break;
        case 6:  // Load Game
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_LoadGame, front);
            break;
        case 7:  // 26 -> Skirmish
            CFrontEndComponent_createScrimishGame(front);
            break;
        case 8:  // Options
        case 15:
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_Options, front);
            break;
        case 9:
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_TodaysTopKeepers, front);
            CButton_handleLeftClick_changeMenu(0, 61, front);
            break;
        case 10:
            g_pathAnimationEndSwitch = 0;
            CButton_handleLeftClick_changeMenu(0, 62, front);
            break;
        case 11:
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_ViewMovies, front);
            CButton_handleLeftClick_changeMenu(0, 59, front);
            break;
        case 12:  // 28 -> Main_Options.Apply
            g_pathAnimationEndSwitch = 0;
            if (patch::auto_network::main(front)) break;
            changeGui(1, MWID_Main, front);
            break;
        case 13:
        case 25:  // Extras
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_Extras, front);
            break;
        case 14:
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_SinglePlayer, front);
            break;
        case 16:  // My Pet Dungeon
            do_smth_and_execute_action_91(front);
            break;
        case 17:  // Extras->Credits
            g_pathAnimationEndSwitch = 0;
            changeGui(1, MWID_Credits, front);
            break;
        case 18:
            CFrontEndComponent_sub_538B90(0, front);
            break;
        case 20:
            CFrontEndComponent_sub_53A010(1, front);
            break;
        case 22:
            CFrontEndComponent_sub_53C3C0(2, front);
            break;
        case 23:
            CFrontEndComponent_sub_53C3C0(3, front);
            break;
        case 26:  // Skirmish
            g_pathAnimationEndSwitch = 7;
            break;
        case 27:
            CFrontEndComponent_sub_53C3C0(1, front);
            break;
        case 28:  // Main_Options.Apply || Main_Extras.Apply
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x112u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 12;
            break;
        case 29:
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x112u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 14;
            break;
        default:
            if (patch::custom_campaign::enabled) {
                if (g_pathAnimationEndSwitch == patch::custom_campaign::animEndAction) {
                    g_pathAnimationEndSwitch = 0;
                    changeGui(1, MWID_SinglePlayer_CustomCampaign, front);
                }
            }
            return;
        }
    }
}

void __cdecl dk2::CFrontEndComponent_subTickMainGui(CFrontEndComponent *a1_front) {
    int status;
    MySound_ptr->v_fun_567BE0(255);
    CSpeechSystem_instance.SetMusicVolume(1);
    MySound_ptr->v_fun_5674F0();

    uint8_t cmd_buf[sizeof(TbSysCommand_Process)];
    TbSysCommand_Process &cmd = *(TbSysCommand_Process *) cmd_buf;
    // v14_cmd.__vftable = (TbSysCommand_Process_vtbl *)&TbSysCommand::Process::`vftable';
    *(void **) &cmd = TbSysCommand_Process::vftable;
    MySound_ptr->v_fun_567A40(&cmd.status, &cmd);

    CFrontEndComponent *v1_front = a1_front;
    if ( a1_front->_aBool_221 == 1 ) {
        CWindow *curWin = a1_front->getCurrentWindow();
        if (curWin) {
            if (curWin->f40_id != 44)
                v1_front->_aBool_221 = 0;
        }
    }
    bool v3 = v1_front->cgui_manager.sub_52C520();
    int v4_usingIme = v1_front->usingIme;
    if (v3) {
        if (!v4_usingIme) {
            HWND HWindow = getHWindow();
            MyInputMethodEditor_instance2.replaceWndProc(&status, HWindow);
            v1_front->usingIme = status == 0;
        }
        CWindow *GameWindowById = v1_front->cgui_manager.findGameWindowById(47);
        CWindow_sub_547B40(GameWindowById, v1_front);
    } else {
        if (v4_usingIme == 1)
            MyInputMethodEditor_instance2.restoreWndProc();
        v1_front->usingIme = 0;
    }
    if (!g_isMainGuiIntroduction) {
        switch (MyResources_instance.playerCfg.mgIntroSwitch) {
        case 0x25:
            CFrontEndComponent_sub_538B90(0, v1_front);
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = v1_front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0xFBu, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 2;
            g_isMainGuiIntroduction = 1;
            break;
        case 9:
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = v1_front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x103u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 7;
            g_isMainGuiIntroduction = 1;
            break;
        case 0xB:
        case 0xA:
        case 0x27:
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = v1_front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x100u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 5;  // Multiplayer game
            g_isMainGuiIntroduction = 1;
            break;
        case 0x26:
            if (!MyResources_instance.gameCfg.useFe2d_unk1) {
                CCamera *cam = v1_front->bridge->v_getCamera();
                cam->flags_E3C |= 8u;
                cam->loadEnginePath(0x108u, 3u, 0xCu, 1);
            }
            g_maybeGuiIsShowing = 0;
            g_pathAnimationEndSwitch = 16;
            g_isMainGuiIntroduction = 1;
            break;
        default:
            break;
        }
    }
    if (MyResources_instance.gameCfg.useFe2d_unk1) {
        if (g_bg2d_loaded[g_surfIdx_6AD608]) {
            static_MyDdSurfaceEx_BltWait(
                &status, v1_front->pMyDdSurfaceEx, 0, 0,
                &g_bg2d_surface[g_surfIdx_6AD608], 0, 0
            );
        }
        if (MyResources_instance.gameCfg.useFe2d_unk1) {
            execSwitch(v1_front);
            return;
        }
    }
    if (v1_front->bridge->v_getCamera()->_mode != 18) {
        execSwitch(v1_front);
    }
}


