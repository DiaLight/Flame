//
// Created by DiaLight on 25.01.2025.
//

#include "dk2_functions.h"
#include "dk2/CFrontEndComponent.h"
#include "dk2/button/CButton.h"
#include "dk2/button/CListBox.h"
#include "dk2/button/CTextInput.h"
#include "dk2/button/CVerticalSlider.h"
#include "dk2_globals.h"
#include "weanetr_dll/MLDPlay.h"
#include "dk2/dk2_memory.h"


namespace dk2 {
    bool handle85(CFrontEndComponent *comp) {
        if (comp->pStrings) {
            dk2::operator_delete(comp->pStrings);
            comp->pStrings = 0;
        }
        if (MyResources_instance.gameCfg.useFe_unk3 != 1) return false;
        uint8_t fC_levelNumber;
        if (MyResources_instance.playerCfg.secretLevelNumber) {
            fC_levelNumber = LOBYTE(MyResources_instance.playerCfg.secretLevelNumber) + 25;
        } else {
            fC_levelNumber = MyResources_instance.playerCfg.levelNumber;
            if (MyResources_instance.playerCfg.getPlayerLevelStatus(MyResources_instance.playerCfg.levelNumber) ==
                1) {
                int resultLevelNumber;
                switch (fC_levelNumber) {
                    case 1u:
                    case 2u:
                    case 3u:
                    case 4u:
                    case 5u:
                    case 0x14u:
                    case 0x15u:
                    case 0x16u:
                    case 0x17u:
                    case 0x18u:
                        resultLevelNumber = fC_levelNumber + 1;
                        break;
                    case 6u:
                    case 7u:
                        resultLevelNumber = 8;
                        break;
                    case 8u:
                    case 9u:
                    case 0xAu:
                    case 0xBu:
                        resultLevelNumber = fC_levelNumber + 1;
                        break;
                    case 0xCu:
                    case 0xDu:
                    case 0xEu:
                        resultLevelNumber = 15;
                        break;
                    case 0xFu:
                    case 0x10u:
                    case 0x11u:
                        resultLevelNumber = fC_levelNumber + 1;
                        break;
                    case 0x12u:
                    case 0x13u:
                        resultLevelNumber = 20;
                        break;
                    default:
                        break;
                }
                if (MyResources_instance.playerCfg.getPlayerLevelStatus(resultLevelNumber) != 1
                    && MyResources_instance.playerCfg.getPlayerLevelStatus(resultLevelNumber) != 3) {
                    MyResources_instance.playerCfg.saveLevelNumber((HKEY) resultLevelNumber);
                }
            }
        }
        if (MyResources_instance.gameCfg.useFe2d_unk1) {
            CSpeechSystem_instance.add_stop_handle0(0);
        } else {
            CSpeechSystem_instance.add_stop_handle0(90);
        }
        if (!MyResources_instance.playerCfg.sub_561E40(3u)->aBool_30) return false;
        int v51_evilRating = MyResources_instance.playerCfg.readTotalEvilRating(fC_levelNumber);
        if (!comp->sub_53E240(v51_evilRating)) return false;
        comp->levelNumber_462 = fC_levelNumber;
        comp->sub_53E320(fC_levelNumber);
        return true;
    }
    bool handle83(CFrontEndComponent *comp) {
        WeaNetR_instance.enumerateSessions(0);
        comp->clear_MyPlayerConfig_instance_arr__setupMpGui();
        CTextInput *v42_foundBtn_530 = NULL;
        for(CButton *cur = comp->cgui_manager.findGameWindowById(11)->f66_buttons; cur; cur = cur->f78_next) {
            if (cur->f70_idx != 530) continue;
            v42_foundBtn_530 = (CTextInput *) cur;
            break;
        }
        if (!v42_foundBtn_530) return true;
        const wchar_t *v43_wstr = (const wchar_t *) v42_foundBtn_530->v_fun_52CA90();
        if (!v43_wstr) return false;
        size_t v44_wstr_len = wcslen(v43_wstr);
        for(size_t v45_i = 0; v45_i < v44_wstr_len; ++v45_i) {
            if (iswdigit(v43_wstr[v45_i])) continue;
            return false;
        }
        __int16 v47_addrPort = _wtoi(v43_wstr);
        if (v47_addrPort == MyResources_instance.networkCfg.addrPort) return true;
        if (comp->setupPlayService(v47_addrPort)) return true;
        return false;
    }
}


int __cdecl dk2::CButton_leftClick_changeMenu(uint32_t idx, int command, CFrontEndComponent *comp) {
    g_mouseAct_bool73EDA0 = 0;
    g_button73ED9C = 0;
    switch (command) {
        case 7:
            if (static_DirFileList_instance2_saves_sav_getCount() > 0) {
                comp->fun_532090((CComponent *) comp);
                DirFileList_instance2_saves_sav.reset();
            }
            break;
        case 8:
            comp->f30344 = 9;
            comp->fun_533460(1);
            fillNetworkStringList();
            comp->f30C1E = 0;
            break;
        case 9:
            if (g_network_string_list) {
                dk2::operator_delete(g_network_string_list);
                g_network_string_list = 0;
            }
            break;
        case 10: {
            comp->f30C1E = 0;
            CSpeechSystem_instance.add_stop_handle0(90);
            g_petDungeonLevelIdx = 0;
            if (MyResources_instance.gameCfg.useFe_playMode == 1) {
                CFrontEndComponent_static_539490(0xFEu, 2, comp);
            } else if (MyResources_instance.gameCfg.useFe_playMode == 4) {
                if (comp->wstr19[0]) {
                    wchar_t *v3_wstr19 = __get_wstr19(0);
                    if (v3_wstr19)
                        wcscpy(comp->wstr19, v3_wstr19);
                    __unk_before_action(1, 48, comp);
                } else {
                    __unk_before_action(1, 38, comp);
                }
            }
            int *v4_pIsLoaded = comp->Shots_ddSurfArr_isLoaded;
            MyDdSurfaceEx *v5_ddSurfPos = comp->Shots_ddSurfArr_30E68;
            int v6_left = 2;
            do {
                if (*v4_pIsLoaded && MyDdSurface_addRef(&v5_ddSurfPos->dd_surf, 0)) {
                    int v68_status;
                    MyDdSurface_release(&v68_status, &v5_ddSurfPos->dd_surf);
                }
                *v4_pIsLoaded++ = 0;
                ++v5_ddSurfPos;
                --v6_left;
            } while (v6_left);
        } break;
        case 11: {
            unsigned __int8 v8_i = 1;
            g_flags_74034C &= ~6;
            unsigned int v9_num = 1;
            do {
                MyResources_instance.playerCfg.savePlayerLevelStatus(v8_i, 0);
                MyResources_instance.playerCfg.saveTotalEvilRating(v9_num, 0);
                ++v8_i;
                ++v9_num;
            } while (v8_i <= 25u);
            unsigned int v10_num = 1;
            int v11_left = 40;
            do {
                MyResources_instance.playerCfg.sub_561A20_levelAttempts(v10_num++);
                --v11_left;
            } while (v11_left);
            MyResources_instance.playerCfg.savePlayerLevelStatus(1, 2);
            MyResources_instance.playerCfg.saveSecretLevels();
            MyResources_instance.playerCfg.saveSecretLevelsCompleted();
            MyResources_instance.playerCfg.saveLevelNumber((HKEY) 1);
            MyResources_instance.playerCfg.saveMpdLevelNumber((HKEY) 1);
            MyResources_instance.playerCfg.fB39 = 0;
        } break;
        case 12: {
            Pos2i String;
            String.x = 0;
            String.y = 0;
            int v68_status;
            static_MyInputManagerCb_sub_5B2BD0(&v68_status, 0, 0, &String);
            if (comp->f6011) {
                MyResources_instance.gameCfg.unk_f16C = 1;
                CSpeechSystem_instance.add_stop_handle(
                        (void *) comp->f311A2,
                        CSpeechSystem_instance.f154,
                        0,
                        50);
            } else {
                g_flags_74034C |= 0xC00;
            }
            switch (MyResources_instance.gameCfg.useFe_playMode) {
                case 3:
                    MyResources_instance.playerCfg.f4 = 27;
                    break;
                case 1:
                    MyResources_instance.playerCfg.f4 = 26;
                    break;
                case 4:
                    MyResources_instance.playerCfg.f4 = 42;
                    break;
                case 2:
                    MyResources_instance.playerCfg.f4 = 45;
                    break;
            }
            memset(comp->wstr19, 0, 0x208u);
            comp->fun_552C80((CComponent *) &CGameComponent_instance);
        } break;
        case 13:
            if (comp->fun_54DB20()) {
                memset(comp->mbStr, 0, sizeof(comp->mbStr));
                comp->fun_548610();
                comp->f601A = 1;
            } else {
                comp->fun_536BA0(0, 0, 2079, 105, 0, 1, 0, 0, 0);
            }
            break;
        case 19:
            DirFileList_instance2_saves_sav.reset();
            comp->f30C1E = 0;
            CFrontEndComponent_static_539490(0x110u, 29, comp);
            break;
        case 20: {
            DirFileList_instance2_saves_sav.collectFiles(MyResources_instance.savesDir, "*.sav", 1);
            CButton *v15_button = NULL;
            for (CButton *f66_buttons = comp->cgui_manager.findGameWindowById(8)->f66_buttons;
                    f66_buttons; f66_buttons = f66_buttons->f78_next
            ) {
                if (f66_buttons->f70_idx != 73) continue;
                v15_button = f66_buttons;
                break;
            }
            if (v15_button)
                v15_button->f5D_isVisible = static_DirFileList_instance2_saves_sav_getCount() > 0;
        } break;
        case 21:
            comp->f30344 = 7;
            comp->clear_MyPlayerConfig_instance_arr__setupMpGui();
            comp->fun_549D10();
            comp->fun_533460(0);
            if (comp->fun_53EF60(2u, comp->playersCount))
                comp->fun_53F7F0(comp->mapName);
            break;
        case 22:
            if (g_network_string_list) {
                dk2::operator_delete(g_network_string_list);
                g_network_string_list = 0;
            }
            comp->f30C1E = 0;
            CFrontEndComponent_static_539490(0x110u, 28, comp);
            break;
        case 23: { // exit action
            WeaNetR_instance.enumerateSessions(0);
            if (g_networkStrInfo) {
                dk2::operator_delete(g_networkStrInfo);
                g_networkStrInfo = 0;
            }
            static_MLDPLAY_SESSIONDESC_arr_reset();
            g_MLDPLAY_SESSIONDESC_arr_count = 0;
            CButton *v17_foundBtn_223 = NULL;
            for (CButton *f78_next = comp->cgui_manager.findGameWindowById(11)->f66_buttons; f78_next; f78_next = f78_next->f78_next) {
                if (f78_next->f70_idx != 223) continue;
                v17_foundBtn_223 = f78_next;
                break;
            }
            CButton *v18_foundBtn_578 = NULL;
            for (CButton *curBtn = comp->cgui_manager.findGameWindowById(39)->f66_buttons; curBtn; curBtn = curBtn->f78_next) {
                if (curBtn->f70_idx != 578) continue;
                v18_foundBtn_578 = curBtn;
                break;
            }
            v17_foundBtn_223->field_63 = 0;
            v18_foundBtn_578->field_63 = 0;  // devs has no NULL checks here
            CFrontEndComponent_static_sub_5457A0(0, 0, comp);
            fillNetworkStringList();
            comp->f30344 = 9;
            comp->f30C1E = 0;
        } break;
        case 24:
            comp->f30C1E = 0;
            CFrontEndComponent_static_539490(0x110u, 29, comp);
            break;
        case 26:
            comp->f30344 = 3;
            comp->sub_54B4B0();
            break;
        case 27:
        case 31:
            comp->f30C1E = 0;
            break;
        case 28: {
            int v19_masterVolume = comp->masterVolume;
            comp->f30C1E = 0;
            MyResources_instance.soundCfg.setMasterVolume(v19_masterVolume);
            MyResources_instance.soundCfg.setMusicVolume(comp->musicVolume);
            MyResources_instance.soundCfg.setSoundEffectVolume(comp->soundEffectVolume);
            MyResources_instance.soundCfg.setSpeechVolume(comp->speechVolume);
            MyResources_instance.soundCfg.setHeadphones(comp->headphones);
            MyResources_instance.soundCfg.setQSound(comp->qSound);
            MyResources_instance.soundCfg.setEnvironmentalEffects(comp->environmentalEffects);
            MyResources_instance.soundCfg.setSoundQuality(comp->soundQuality);
        } break;
        case 29:
            comp->f30344 = 1;
            comp->sub_54B060();
            comp->f30C1E = 0;
            break;
        case 30:
            comp->sub_54BB80();
            comp->f30C1E = 0;
            break;
        case 32: {
            WeaNetR_instance.enumerateSessions(0);
            comp->sub_54DEC0(204, 230, 10, comp);
            comp->sub_54E8B0(230, 10);
            comp->clear_MyPlayerConfig_instance_arr__setupMpGui();
            if (comp->createMultiplayerGame() == 1 && comp->sub_546680(10) == 1) {
                MyResources_instance.gameCfg.f150 = 1;
                comp->fun_549D10();
                break;
            }
            uint8_t *MbString = MyMbStringList_idx1091_getMbString(0x613u);
            strcpy((char *) comp->mbStr, (const char *) MbString);
            comp->f30C1E = 0;
            comp->f30344 = 12;
            comp->fun_5321A0(10, 10);
        } break;
        case 33:
            if (!WeaNetR_instance.descArr_count || g_listItemNum == -1) {
                uint8_t *MbString = MyMbStringList_idx1091_getMbString(0x611u);
                strcpy((char *) comp->mbStr, (const char *) MbString);
            } else {
                if (comp->f602B[g_listItemNum] == 1) {
                    comp->clear_MyPlayerConfig_instance_arr__setupMpGui();
                    comp->sub_54DEC0(204, 230, 10, comp);
                    if (comp->joinMultiplayerGame(g_listItemNum) == 1) {
                        WeaNetR_instance.enumerateSessions(0);
                        comp->f30C1E = 2;
                        comp->f30344 = 16;
                        comp->fun_5321A0(32, 10);
                        comp->sub_5453F0();
                        comp->f6037 = 10;
                        MyResources_instance.gameCfg.f150 = 0;
                        break;
                    }
                }
                uint8_t *v62_mbstr = MyMbStringList_idx1091_getMbString(0x611u);
                strcpy((char *) comp->mbStr, (const char *) v62_mbstr);
            }
            comp->f30C1E = 0;
            comp->f30344 = 12;
            comp->fun_5321A0(10, 10);
            break;
        case 42:
            comp->f30C1E = 0;
            wcsncpy(MyResources_instance.gameCfg.levelName, comp->mapName, 0x40u);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            comp->sub_549F60();
            comp->sub_5435E0(0, comp);
            break;
        case 43:
            comp->f30344 = 5;
            break;
        case 56: {
            comp->copyDxKeysToConfig();
            if (comp->pActionToDxKey) {
                dk2::operator_delete(comp->pActionToDxKey);
                comp->pActionToDxKey = 0;
            }
            int f31176_mouseSensitivity = comp->mouseSensitivity;
            comp->f30C1A = 0;
            MyResources_instance.playerCfg.saveMouseSensitivity(f31176_mouseSensitivity);
            comp->f30C1E = 0;
        } break;
        case 57:
            comp->f30C1A = 0;
            comp->saveMouseCfg();
            if (!comp->pActionToDxKey) {
                comp->f30C1E = 0;
                break;
            }
            dk2::operator_delete(comp->pActionToDxKey);
            comp->pActionToDxKey = 0;
            comp->f30C1E = 0;
            break;
        case 58:
            comp->sub_54C240();
            comp->f30344 = 2;
            comp->sub_54B780();
            comp->f30C1E = 0;
            break;
        case 59:
            comp->f30344 = 8;
            comp->f30C1E = 0;
            comp->sub_53B3F0(5);
            break;
        case 60:
            comp->sub_53B950();
            comp->f30C1E = 0;
            break;
        case 61:
            comp->f30344 = 6;
            comp->f30C1E = 0;
            break;
        case 62: {
            char trailerFilePath[260];
            memset(trailerFilePath, 0, sizeof(trailerFilePath));
            sprintf(trailerFilePath, "%s\\Trailer.tgq", MyResources_instance.dataMoviesDir);
            comp->showMovie(trailerFilePath);
        } break;
        case 65: {
            comp->f30C1E = 0;
            CButton *v20_foundBtn_47 = NULL;
            for(CButton *curBtn = comp->cgui_manager.findGameWindowById(18)->f66_buttons; curBtn; curBtn = curBtn->f78_next) {
                if (curBtn->f70_idx != 47) continue;
                v20_foundBtn_47 = curBtn;
                break;
            }
            if (v20_foundBtn_47)
                v20_foundBtn_47->f55__nextWindowIdOnClick = 6;
        } break;
        case 69:
            comp->f30344 = 15;
            break;
        case 70: {
            comp->saveAddressBookWinsock(1);
            comp->f30344 = 15;
            CButton *v53_foundBtn_223 = 0;
            for(CButton *cur = comp->cgui_manager.findGameWindowById(11)->f66_buttons; cur; cur = cur->f78_next) {
                if (cur->f70_idx != 223) continue;
                v53_foundBtn_223 = cur;
                break;
            }
            CButton *v54_foundBtn_578 = NULL;
            for(CButton *cur = comp->cgui_manager.findGameWindowById(39)->f66_buttons; cur; cur = cur->f78_next) {
                if(cur->f70_idx != 578) continue;
                v54_foundBtn_578 = cur;
                break;
            }
            v53_foundBtn_223->field_63 = 0;
            v54_foundBtn_578->field_63 = 0;
            CFrontEndComponent_static_sub_5457A0(0, 0, comp);
        } break;
        case 72:
        case 87:
            g_flags_74034C &= ~8u;
            comp->f30344 = 17;
            comp->f30C1E = 0;
            comp->f603B = 0;
            comp->f3133 = -1;
            comp->sub_549160();
            comp->fun_549D10();
            if (command == 72) {
                comp->wndId_6016 = 32;
            } else {
                comp->wndId_6016 = 9;
            }
            break;
        case 77:
        case 88: {
            int f6608_mapIdx = comp->mapIdx_6608;
            comp->f30344 = 18;
            comp->mapIdx_6033 = f6608_mapIdx;
            CListBox *foundBtn = NULL;
            if (command == 77) {
                comp->f30C1E = 3;
                comp->wndId_6016 = 32;
                for (CListBox *cur = (CListBox *) comp->cgui_manager.findGameWindowById(33)->f66_buttons; cur; cur = (CListBox *) cur->f78_next) {
                    if (cur->f70_idx != 469) continue;
                    foundBtn = cur;
                    break;
                }
            } else {
                comp->f30C1E = 1;
                comp->wndId_6016 = 9;
                for (CListBox *cur = (CListBox *) comp->cgui_manager.findGameWindowById(34)->f66_buttons; cur; cur = (CListBox *) cur->f78_next) {
                    if (cur->f70_idx != 477) continue;
                    foundBtn = cur;
                    break;
                }
            }
            if (foundBtn) ((CVerticalSlider *) foundBtn->f78_next)->v_fun_529000(0);
            CFrontEndComponent_sub_5415D0(0, 0, comp);
        } break;
        case 78:
            if (comp->wndId_6016 == 32) {
                int v64_isZero = comp->mp_isHost == 0;
                comp->f30344 = 16;
                comp->f30C1E = 2;
                comp->sub_53FAA0(v64_isZero);
                comp->fun_5321A0(comp->wndId_6016, 33);
            } else {
                comp->f30344 = 7;
                comp->f30C1E = 1;
                comp->sub_53FAA0(1);
                comp->fun_5321A0(comp->wndId_6016, 34);
            }
            g_flags_74034C = g_flags_74034C & ~0xE | 2;
            break;
        case 79: {
            int v24_wndId = comp->wndId_6016;
            int f311F2_mp_isHost = 0;
            if (v24_wndId == 32) {
                f311F2_mp_isHost = comp->mp_isHost;
                comp->f30344 = 16;
            } else {
                comp->f30344 = 7;
            }
            if (f311F2_mp_isHost || v24_wndId == 9) {
                int f6033_mapIdx = comp->mapIdx_6033;
                comp->mapIdx_6608 = f6033_mapIdx;
                comp->sub_53FC40(f6033_mapIdx);
                loadThumbnail(comp->mapName, (MyDdSurfaceEx *) comp);
                int v26_wndId = comp->wndId_6016;
                if (v26_wndId == 9) {
                    comp->f30C1E = 1;
                    comp->fun_5321A0(9, 34);
                } else {
                    comp->f30C1E = 2;
                    comp->fun_5321A0(v26_wndId, 33);
                }
            } else {
                comp->f30344 = 16;
                comp->f30C1E = 0;
                comp->fun_5321A0(v24_wndId, 34);
            }
            g_flags_74034C = g_flags_74034C & 0xFFFFFFF1 | 2;
        } break;
        case 80: {
            if (comp->wndId_6016 == 32) {
                comp->f30344 = 16;
                comp->f30C1E = 2;
                if (comp->mp_isHost) comp->sub_549F60();
            } else {
                comp->f30344 = 7;
                comp->f30C1E = 2;
                comp->sub_549F60();
            }
            comp->fun_5321A0(comp->wndId_6016, 35);
            g_flags_74034C = g_flags_74034C & 0xFFFFFFF1 | 2;
        } break;
        case 81: {
            g_flags_74034C = g_flags_74034C & 0xFFFFFFF1 | 2;
            comp->fun_549D10();
            int f6016_wndId_6016 = comp->wndId_6016;
            if (f6016_wndId_6016 == 32) {
                comp->f30344 = 16;
                comp->f30C1E = 2;
                comp->fun_5321A0(32, 35);
            } else {
                comp->f30344 = 7;
                comp->f30C1E = 1;
                comp->fun_5321A0(f6016_wndId_6016, 35);
            }
        } break;
        case 82: {
            g_networkIsHost_740360 = 0;
            comp->fun_536E20(1, 1);
            if (comp->f2E5F) {
                dk2::operator_delete((void *) comp->f2E5F);
                comp->f2E5F = 0;
            }
            if (comp->f30CAB) {
                dk2::operator_delete((void *) comp->f30CAB);
                comp->f30CAB = 0;
            }
            comp->f30C1E = 0;
            memset(g_MyPlayerConfig_instance_arr, 0, sizeof(g_MyPlayerConfig_instance_arr));
            unsigned int v34_playerIdx = 0;
            if (comp->playersCount) {
                MyPlayerConfig *p_f3A_flags = &g_MyPlayerConfig_instance_arr[0];
                do {
                    uint8_t f3A_flags = p_f3A_flags->flags;
                    *(BYTE *) &p_f3A_flags->name_or_aiId[0] = f3A_flags & 0xF0;
                    p_f3A_flags++;
                    ++v34_playerIdx;
                } while (v34_playerIdx < comp->playersCount);
            }
            WeaNetR_instance.mldplay->DestroySession();
            BOOL v38_failedToInitService = 1;
            if (WeaNetR_instance.reinitializeNetworkSystem()) {
                int f30315_weanetrServiceIdx = comp->weanetrServiceIdx;
                Pos2i String;
                String.x = 0;
                String.y = 0;
                int Service = WeaNetR_instance.getService(f30315_weanetrServiceIdx, (FoundPlayService *) &String);
                v38_failedToInitService = Service == 0;
                if (Service)
                    v38_failedToInitService = !static_WeaNetR_setupService((FoundPlayService *) &String);
                if (g_networkStrInfo) {
                    dk2::operator_delete(g_networkStrInfo);
                    g_networkStrInfo = 0;
                }
                static_MLDPLAY_SESSIONDESC_arr_reset();
                g_MLDPLAY_SESSIONDESC_arr_count = 0;
                CButton *v40_foundBtn_223 = NULL;
                for(CButton *cur = comp->cgui_manager.findGameWindowById(11)->f66_buttons; cur; cur = cur->f78_next) {
                    if (cur->f70_idx != 223) continue;
                    v40_foundBtn_223 = cur;
                    break;
                }
                CButton *v41_foundBtn_578 = NULL;
                for(CButton *cur = comp->cgui_manager.findGameWindowById(39)->f66_buttons; cur; cur = cur->f78_next) {
                    if (cur->f70_idx != 578) continue;
                    v41_foundBtn_578 = cur;
                    break;
                }
                v40_foundBtn_223->field_63 = 0;
                v41_foundBtn_578->field_63 = 0;
                CFrontEndComponent_static_sub_5457A0(0, 0, comp);
                comp->findAndSetButtonVisible(577, 39, 0);
                comp->findAndSetButtonVisible(224, 11, 0);
                comp->findAndSetButtonVisible(207, 10, 0);
                comp->sub_5466E0(comp->f6037);
                if (idx != 1)
                    comp->fun_5321A0(comp->f6037, 32);
            }
            comp->fun_536E20(1, 0);
            if (v38_failedToInitService)
                comp->fun_536BA0(0, 0, 2079, 105, 0, 1, 0, 0, 0);
        } break;
        case 83: {
            if(handle83(comp)) {
                comp->sub_54DEC0(221, 227, 11, comp);
                comp->sub_54E8B0(227, 11);
                if (comp->createMultiplayerGame() == 1 && comp->sub_546680(11) == 1) {
                    MyResources_instance.gameCfg.f150 = 1;
                    comp->fun_549D10();
                    break;
                }
            }
            unsigned __int8 *v48_mbStr_613 = MyMbStringList_idx1091_getMbString(0x613u);
            strcpy((char *) comp->mbStr, (const char *) v48_mbStr_613);
            comp->f30C1E = 0;
            comp->f30344 = 12;
            comp->fun_5321A0(11, 11);
        } break;
        case 84:
            comp->sub_537AE0(0x1Bu);
            comp->fun_536E20(1, 1);
            WeaNetR_instance.enumerateSessions(0);
            if (g_MLDPLAY_SESSIONDESC_arr_count) {
                if (g_listItemNum != -1 && comp->f602B[g_listItemNum] == 1) {
                    comp->clear_MyPlayerConfig_instance_arr__setupMpGui();
                    comp->sub_54DEC0(221, 227, 11, comp);
                    if (comp->joinMultiplayerGame(g_listItemNum) == 1) {
                        comp->f30C1E = 2;
                        comp->f30344 = 16;
                        comp->fun_5321A0(32, 11);
                        comp->sub_5453F0();
                        comp->f6037 = 11;
                        comp->fun_536E20(1, 0);
                        MyResources_instance.gameCfg.f150 = 0;
                        break;
                    }
                }
            }
            comp->f30C1E = 0;
            comp->f30344 = 12;
            comp->fun_5321A0(11, 11);
            comp->fun_536E20(1, 0);
            break;
        case 85: {
            if(!handle85(comp)) CFrontEndComponent_static_539490(0xFEu, 18, comp);
        } break;
        case 86:
            comp->f30344 = 19;
            comp->f30C1E = 0;
            comp->saveAddressBookWinsock(0);
            break;
        case 89:
            CSpeechSystem_instance.add_stop_handle0(90);
            g_petDungeonLevelIdx = 0;
            static_CFrontEndComponent_updateRenderInfo_flags();
            CFrontEndComponent_static_539490(0xFCu, 14, comp);
            break;
        case 90: {
            if (comp->f6011) {
                MyResources_instance.gameCfg.unk_f16C = 1;
            } else {
                g_flags_74034C |= 0xC00;
            }
            int v56_playerIdx = comp->playerIdx11;
            int v57_left = 7;
            do {
                char v58_playerType = g_MyPlayerConfig_instance_arr[v56_playerIdx].flags & 7;
                if (v58_playerType == 1) {  // ai player
                    MyResources_instance.gameCfg.aiType[(unsigned __int8) v56_playerIdx] = *(DWORD *) g_MyPlayerConfig_instance_arr[v56_playerIdx].name_or_aiId;
                } else if (v58_playerType == 2 || v58_playerType == 3) {  // human player
                    MyResources_instance.gameCfg.aiType[(unsigned __int8) v56_playerIdx] = 255;
                } else {  // no player
                    MyResources_instance.gameCfg.aiType[(unsigned __int8) v56_playerIdx] = 9;
                }
                if ((unsigned int) ++v56_playerIdx >= 7)
                    v56_playerIdx = 0;
                --v57_left;
            } while (v57_left);
            MyResources_instance.gameCfg._aiPlayercount = g__aiPlayersCount;
            MyResources_instance.gameCfg.useFe_playMode = 2;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
            wcsncpy(MyResources_instance.gameCfg.levelName, comp->mapName, 0x40u);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            MyResources_instance.playerCfg.f4 = 45;
            comp->sub_549F60();
            comp->fun_552C80((CComponent *) &CGameComponent_instance);
        } break;
        case 92:
        case 95:
            CFrontEndComponent_sub_53A010(1, comp);
            break;
        case 93:
            CFrontEndComponent_static_539490(0x107u, 28, comp);
            break;
        case 96:
            memset(comp->wstr19, 0, 0x208u);
            break;
        case 97:
            comp->sub_537AE0(0x1Bu);
            comp->fun_536E20(1, 1);
            WeaNetR_instance.enumerateSessions(0);
            if (g_MLDPLAY_SESSIONDESC_arr_count
                && g_listItemNum != -1
                && comp->f602B[g_listItemNum] == 1
                && (comp->clear_MyPlayerConfig_instance_arr__setupMpGui(),
                    comp->sub_54DEC0(584, 0, 39, comp),
                    comp->joinMultiplayerGame(g_listItemNum) == 1)) {
                comp->f30C1E = 2;
                comp->f30344 = 16;
                comp->fun_5321A0(32, 39);
                comp->sub_5453F0();
                comp->f6037 = 39;
                comp->fun_536E20(1, 0);
                MyResources_instance.gameCfg.f150 = 0;
            } else {
                uint8_t *v49_mbString_611 = MyMbStringList_idx1091_getMbString(0x611u);
                strcpy((char *) comp->mbStr, (const char *) v49_mbString_611);
                comp->f30C1E = 0;
                comp->f30344 = 12;
                comp->fun_5321A0(39, 39);
                comp->fun_536E20(1, 0);
            }
            break;
        case 98:
            CFrontEndComponent_static_539490(0x10Au, 13, comp);
            comp->sub_53B3D0();
            break;
        case 99:
            CFrontEndComponent_static_539490(0x109u, 17, comp);
            break;
        case 100:
            g_petDungeonLevelIdx = 0;
            static_CFrontEndComponent_updateRenderInfo_flags();
            CFrontEndComponent_static_539490(0x10Cu, 12, comp);
            break;
        case 101:
            g_idxLow_740348 = 0;
            memset(comp->wstr19, 0, 0x208u);
            break;
        case 104: {
            comp->sub_53DB30();
            comp->sub_53E610(comp->levelNumber_462);
            uint32_t v70_status;
            comp->sub_53D870(&v70_status, "Data\\Settings\\HiScores.dat");
            comp->f30C1E = 0;
            CFrontEndComponent_static_539490(0xFEu, 18, comp);
            CButton *v59_wnd18_buttons = comp->cgui_manager.findGameWindowById(18)->f66_buttons;
            if (v59_wnd18_buttons != nullptr) {
                while (v59_wnd18_buttons->f70_idx != 47) {
                    v59_wnd18_buttons = v59_wnd18_buttons->f78_next;
                    if (!v59_wnd18_buttons) {
                        v59_wnd18_buttons = 0;
                        break;
                    }
                }
            }
            if (v59_wnd18_buttons) v59_wnd18_buttons->f55__nextWindowIdOnClick = 0;
        } break;
        case 105:
            comp->fun_5321A0(3, 44);
            break;
        case 106:
            comp->fun_5321A0(5, 44);
            break;
        case 108:
            --comp->_count331;
            comp->fun_5321A0(comp->f6037, 44);
            break;
        case 109:
            CFrontEndComponent_sub_538B90((HKEY) 1, comp);
            CFrontEndComponent_static_539490(0xFBu, 2, comp);
            break;
        case 110:
            comp->fun_5321A0(2, 44);
            break;
        case 111: {
            Pos2i String;
            String.x = 0;
            String.y = 0;
            int v69_status;
            static_MyInputManagerCb_sub_5B2BD0(&v69_status, 0, 0, &String);
            comp->release();
        } break;
        case 112:
            comp->fun_5321A0(1, 44);
            break;
        case 113:
            comp->fun_5321A0(comp->f6037, 32);
            break;
        case 114:
            comp->timeMs = getTimeMs();
            comp->fun_5321A0(32, 44);
            comp->timeMs = getTimeMs();
            break;
        case 115: {
            CFrontEndComponent *v29_comp = comp;
            v29_comp->Obj54401A_arr[idx]._aBool = 0;
            v29_comp->Obj54401A_arr[idx].timeMs = 1;
            v29_comp->Obj54401A_arr[idx].f8 = 0;
            comp->fun_5321A0(32, 44);
            v29_comp->Obj54401A_arr[idx]._aBool = 0;
            v29_comp->Obj54401A_arr[idx].timeMs = 0;
            v29_comp->Obj54401A_arr[idx].f8 = 0;
        } break;
        case 116: {
            CFrontEndComponent *v30_comp = comp;
            v30_comp->Obj54401A_arr[idx]._aBool = 0;
            v30_comp->Obj54401A_arr[idx].timeMs = 0;
            v30_comp->Obj54401A_arr[idx].f8 = 0;
            WeaNetR_instance.mldplay->DumpPlayer(idx);// DestroySession
            int v31_i = 0;
            if (comp->playersCount) {
                MyPlayerConfig *v32_curPlayerCfg = &g_MyPlayerConfig_instance_arr[0];
                do {
                    if (v32_curPlayerCfg->_relations1[idx] == 1)
                        v32_curPlayerCfg->_relations1[idx] = 0;
                    if (v32_curPlayerCfg->_relations2[idx] == 1)
                        v32_curPlayerCfg->_relations2[idx] = 0;
                    ++v31_i;
                    ++v32_curPlayerCfg;
                } while (v31_i < comp->playersCount);
            }
            MyPlayerConfig *v33_playerCfg = &g_MyPlayerConfig_instance_arr[idx];
            memset(v33_playerCfg, 0, sizeof(MyPlayerConfig));
            g_MyPlayerConfig_instance_arr[idx].flags &= 0xF0u;
        } break;
        case 117:
            if (comp->mp_isHost)
                WeaNetR_instance.mldplay->EnableNewPlayers(1);
            comp->sub_548520();
            comp->sub_5453F0();
            comp->fun_5321A0(32, 46);
            break;
        default:
            break;
    }
    int result = WeaNetR_instance.updatePlayers_isHost();
    comp->mp_isHost = result;
    g_listItemNum = 0;
    return result;
}

