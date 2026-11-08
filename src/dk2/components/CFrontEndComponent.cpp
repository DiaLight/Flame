//
// Created by DiaLight on 21.07.2024.
//
#include <dk2/components/CFrontEndComponent.h>
#include <dk2/MyMapInfo.h>
#include <dk2/Obj543D99.h>
#include <dk2/button/CListBox.h>
#include <dk2/button/CTextInput.h>
#include <dk2/network/FoundSessionDesc.h>
#include <dk2/network/MLDPLAY_SESSIONDESC.h>
#include <dk2/network/protocol/NetMessage_65.h>
#include <patches/auto_network.h>
#include <patches/big_resolution_fix/screen_resolution.h>
#include <weanetr_dll/MLDPlay.h>
#include "dk2/CListBox_ItemHeightCfg.h"
#include "dk2/engine/game_engine.h"
#include "dk2/sound/TbSysCommand_GetDirectSoundObject.h"
#include "dk2/sound/TbSysCommand_Process.h"
#include "dk2/sound/TbSysCommand_StopAll.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/dk2_memory.h"
#include "patches/logging.h"
#include "patches/micro_patches.h"
#include "weanetr_dll/globals.h"
#include "patches/preselected_map.h"
#include <bit>
#include "patches/opengl/opengl_patch.h"


void dk2::CFrontEndComponent::showTitleScreen() {
    char Buffer[260];
    if (MyResources_instance.playerCfg.kbLayoutId == 17 ) {
        sprintf(Buffer, "TitleScreen\\TitleScreen-Japanese");
    } else {
        char *LayoutName = MyResources_instance.playerCfg.getLayoutName();
        sprintf(Buffer, "TitleScreen\\TitleScreen");
        if ( _strcmpi(LayoutName, "english") )
            sprintf(Buffer, "TitleScreen\\TitleScreen-%s", LayoutName);
    }
    unsigned __int16 extensionFlags = getResourceExtensionFlags();
    int status;
    loadArtToSurfaceEx(
            &status,
            &this->titleScreen,
            &MyResources_instance.frontEndFileMan,
            Buffer,
            extensionFlags);
    if ( status >= 0 ) {
        static_MyDdSurfaceEx_BltWait(&status, this->pMyDdSurfaceEx, 0, 0, &this->titleScreen, 0, 0);
        MyWindow_instance.prepareScreen();
        if ( MyDdSurface_addRef(&this->titleScreen.dd_surf, 0) )
            MyDdSurface_release(&status, &this->titleScreen.dd_surf);

        if(!patch::skippable_title_screen::enabled) {
            DWORD waitEnd = getTimeMs() + 10000;
            while ( getTimeMs() <= waitEnd ) ;
        } else {
            DWORD waitEnd = getTimeMs() + patch::skippable_title_screen::waiting_time;
            while ( getTimeMs() <= waitEnd && !patch::skippable_title_screen::skipKeyPressed() ) ;
        }
        MyWindow_instance.prepareScreen();
    }
}

dk2::CComponent *dk2::CFrontEndComponent::mainGuiLoop() {
    patch::log::dbg("enter CFrontEndComponent");
    while (!this->is_component_destroy) {
        if (this->cgui_manager.sub_52C520())
            MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                &this->static_listeners, 0, this, 0);
        else
            MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                &this->static_listeners, 1u, this, 0);
        if (IsIconic(getHWindow())) continue;
        this->f10 = 0;
        this->cgui_manager.sub_52BC50((CDefaultPlayerInterface*) this);

        for (CWindow* curWin = &this->cgui_manager.windowListEnd; curWin; curWin = curWin->f5E_next) {
            if (!curWin->f44_isCurrent) continue;
            if (auto* f24_getPanelItemsCount = curWin->f24_getPanelItemsCount)
                f24_getPanelItemsCount(curWin, 0, this);
            break;
        }
        if (this->f10 == 1) continue;
        DWORD nowMs = getTimeMs();
        if (nowMs >= g_lastRedawTime) {
            char sysCmdBuf[sizeof(TbSysCommand_Process)];
            auto &sysCmd = *(TbSysCommand_Process *) sysCmdBuf;
            *(void **) &sysCmd = TbSysCommand_Process::vftable;
            int status;
            g_MySound_ptr->v_fun_567A40(&status, &sysCmd);
            if (this->draw2dGui_0()) {
                MyWindow_instance.prepareScreen();
            }
            g_lastRedawTime = nowMs + 16;
        }
        if (isAppExitStatusSet())
            this->release();
    }
    return this->f4_nextComponent;
}

char dk2::CFrontEndComponent::sub_5435E0(int a2, CFrontEndComponent *a3_comp) {
    if (!g_networkIsHost_740360) return 1;
    if (!WeaNetR_instance.updatePlayers_isHost()) return 1;

    size_t v5_netDataLen = 2 * wcslen(g_selectedMapName_0073FB90) + 2;
    unsigned int v22_p2_sz = 5 * a3_comp->variable_creatures_count;
    unsigned int v24_p3_sz = 5 * a3_comp->variable_p3_traps_sz;
    unsigned int v23_p4_sz = 5 * a3_comp->variable_p4_rooms_sz;
    unsigned int v21_p5_sz = 5 * a3_comp->variable_p5_spells_sz;
    unsigned int v25_p6_sz = 5 * a3_comp->variable_p6_doors_sz;
    size_t v6_bufSize = v22_p2_sz + v24_p3_sz + v23_p4_sz + v21_p5_sz + v25_p6_sz + v5_netDataLen + 22;
    unsigned int v26_bufSize = v6_bufSize;
    BYTE *v7_buf = (BYTE *) malloc_2(v6_bufSize);
    if (!v7_buf) return 0;

    memset(v7_buf, 0, v6_bufSize);
    *v7_buf = 0xC7;
    wcscpy((wchar_t *) (v7_buf + 1), g_selectedMapName_0073FB90);
    BYTE *v8_header = &v7_buf[v5_netDataLen + 1];
    *(DWORD *) v8_header = *(DWORD *) &this->b1_msg6F_start__levelCfg;
    v8_header[4] = this->b5_kickedPlayerMask;

    memcpy(&v7_buf[v5_netDataLen + 6], this->poolValue_p2_creatures, v22_p2_sz);

    unsigned int v9_p3_offs = v22_p2_sz + v5_netDataLen + 6;
    memcpy(&v7_buf[v9_p3_offs], this->availability_p3_traps, v24_p3_sz);

    unsigned int v10_p4_offs = v24_p3_sz + v9_p3_offs;
    memcpy(&v7_buf[v10_p4_offs], this->availability_p4_rooms, v23_p4_sz);

    unsigned int v11_p5_offs = v23_p4_sz + v10_p4_offs;
    memcpy(&v7_buf[v11_p5_offs], this->availability_p5_spells, v21_p5_sz);

    unsigned int v12_p6_offs = v21_p5_sz + v11_p5_offs;
    memcpy(&v7_buf[v12_p6_offs], this->availability_p6_doors, v25_p6_sz);

    BYTE *v13_pRelationsMask1 = &v7_buf[v25_p6_sz + v12_p6_offs];
    MyPlayerConfig *f32_plCfg = &g_MyPlayerConfig_instance_arr[0];
    do {
        char v15_relationsMask1 = 0;
        char v16_relationsMask2 = 0;
        for (unsigned int i = 0; i < 8; ++i) {
            v15_relationsMask1 |= f32_plCfg->_relations1[i] << i;
            v16_relationsMask2 |= f32_plCfg->_relations2[i] << i;
        }
        *v13_pRelationsMask1 = v15_relationsMask1;
        BYTE *v18_pRelationsMask2 = v13_pRelationsMask1 + 1;
        ++f32_plCfg;
        *v18_pRelationsMask2 = v16_relationsMask2;
        v13_pRelationsMask1 = v18_pRelationsMask2 + 1;
    } while (f32_plCfg < &g_MyPlayerConfig_instance_arr[8]);
    net::MLDPLAY_PLAYERINFO v27_playerInfoArr[8];
    memset(v27_playerInfoArr, 0, sizeof(v27_playerInfoArr));
    if (!WeaNetR_instance.mldplay->GetPlayerInfo(v27_playerInfoArr))
        return 0;
    unsigned int v19_i = 0;
    net::MLDPLAY_PLAYERINFO *v20_plInfoPos = v27_playerInfoArr;
    do {
        if ((v20_plInfoPos->f0_flags & 0xF) != 0)
            WeaNetR_instance.sendGuaranteedData(v7_buf, v26_bufSize, v19_i);
        ++v19_i;
        ++v20_plInfoPos;
    } while (v19_i < 8);
    dk2::operator_delete(v7_buf);
    return 1;
}

uint32_t dk2::CFrontEndComponent::broadcastMsg_0x65() {
    unsigned int result = WeaNetR_instance.mldplay->GetCurrentMs() - g_lastTimeMs_73FC20;
    if (result <= 2000) return result;

    if (this->mp_isHost) {
        int f1D4_playersSlot = WeaNetR_instance.playersSlot;
        net::MLDPLAY_PLAYERINFO v7_playerInfoArr[8];
        memset(v7_playerInfoArr, 0, sizeof(v7_playerInfoArr));
        result = WeaNetR_instance.mldplay->GetPlayerInfo(v7_playerInfoArr);
        if (!result) return 0;
        for (int i = 0; i < 8; ++i) {
            net::MLDPLAY_PLAYERINFO *v4_plInfo = &v7_playerInfoArr[i];
            Obj54401A *v5_pos = &this->Obj54401A_arr[i];
            if ((v4_plInfo->f0_flags & 0xF) != 1) continue;
            if ((v4_plInfo->f0_flags & 0xF0) != 0) continue;
            if (i == f1D4_playersSlot) continue;
            this->sendMsg_0x65(i);
            if (v5_pos->timeMs == 0) {
                v5_pos->f8 = 0;
                v5_pos->timeMs = getTimeMs();
                v5_pos->_aBool = 1;
            }
        }
    } else {
        this->sendMsg_0x65((uint16_t) -2);
    }
    result = WeaNetR_instance.mldplay->GetCurrentMs();
    g_lastTimeMs_73FC20 = result;
    return result;
}

char dk2::CFrontEndComponent::sub_54DD10(int a2_isHost) {
    net::MLDPLAY_PLAYERINFO playerInfoArr[8];
    memset(playerInfoArr, 0, sizeof(playerInfoArr));
    if (!WeaNetR_instance.mldplay->GetPlayerInfo(playerInfoArr))
        return 0;
    g__humanPlayersCount = 0;
    unsigned int v4_i = 0;
    net::MLDPLAY_PLAYERINFO *v5_plInfo = playerInfoArr;
    do {
        char f0_flags = v5_plInfo->f0_flags;
        if ((v5_plInfo->f0_flags & 0xF) != 0)
            ++g__humanPlayersCount;
        if ((f0_flags & 0xF0) != 0)
            this->playerIdx11 = v4_i;
        ++v4_i;
        ++v5_plInfo;
    } while (v4_i < 8);
    int v7_isHost = WeaNetR_instance.updatePlayers_isHost();
    this->mp_isHost = v7_isHost;
    if (v7_isHost) {
        int v16_m = 0;
        MyPlayerConfig *v8_plCfg2 = &g_MyPlayerConfig_instance_arr[0];
        Obj54401A *v9_pos = &this->Obj54401A_arr[0];
        do {
            char v10_j = 0;
            while ((playerInfoArr[v10_j].f0_flags & 0xF) == 0
                   || playerInfoArr[v10_j].f26_playerId_slot.value != v8_plCfg2->playerId) {
                if (++v10_j >= 8) {
                    v10_j = -1;
                    break;
                }
            }
            if (v10_j == -1 && (v8_plCfg2->flags & 7) != 1) {
                v9_pos->timeMs = 0;
                v9_pos->_aBool = 0;
                int v11_k = 0;
                if (this->playersCount) {
                    MyPlayerConfig *v12_plCfg = &g_MyPlayerConfig_instance_arr[0];
                    do {
                        if (v12_plCfg->_relations1[v16_m] == 1)
                            v12_plCfg->_relations1[v16_m] = 0;
                        if (v12_plCfg->_relations2[v16_m] == 1)
                            v12_plCfg->_relations2[v16_m] = 0;
                        ++v11_k;
                        ++v12_plCfg;
                    } while (v11_k < this->playersCount);
                }
                memset(v8_plCfg2, 0, sizeof(MyPlayerConfig));
                v8_plCfg2->flags &= 0xF0u;
            }
            ++v8_plCfg2;
            ++v9_pos;
            ++v16_m;
        } while (v8_plCfg2 < &g_MyPlayerConfig_instance_arr[8]);
        static_assert(sizeof(net::MLDPLAY_PLAYERINFO) == sizeof(dk2::MLDPLAY_PLAYERINFO));
        unsigned int v13_n = 0;
        net::MLDPLAY_PLAYERINFO *v14_playerInfo = &playerInfoArr[0];
        net::MLDPLAY_PLAYERINFO *p_f26_playerId = (net::MLDPLAY_PLAYERINFO *) &this->playerInfoArr[0];
        do {
            if ((((unsigned __int8) this->b5_kickedPlayerMask >> v13_n) & 1) == 1) {
                if (p_f26_playerId->f26_playerId_slot == v14_playerInfo->f26_playerId_slot)
                    this->sub_5455A0(v13_n);
                else
                    this->b5_kickedPlayerMask &= ~(1 << v13_n);
            }
            ++v13_n;
            ++p_f26_playerId;
            ++v14_playerInfo;
        } while (v13_n < 8);
    }
    memcpy(this->playerInfoArr, playerInfoArr, sizeof(this->playerInfoArr));
    return 1;
}

char dk2::CFrontEndComponent::sendMsg_0x65(unsigned int a2_playerListIdx_m1_m2) {
    NetMessage_65 v9_dataMsg;
    v9_dataMsg.packetId = 0x65;
    v9_dataMsg.id = g_nextId_73FC1C++;

    if (g_networkIsHost_740360)
        WeaNetR_instance.sendDataMessage(&v9_dataMsg, sizeof(NetMessage_65), a2_playerListIdx_m1_m2);
    unsigned int CurrentMs = WeaNetR_instance.mldplay->GetCurrentMs();
    if (!this->mp_isHost)
        return 1;
    Obj543D99 *v4_obj = (Obj543D99 *) dk2::operator_new(sizeof(Obj543D99));
    Obj543D99 *v5_obj = v4_obj;
    if (v4_obj) {
        v4_obj->playerListIdx_m1_m2 = a2_playerListIdx_m1_m2;
        v4_obj->timeMs = CurrentMs;
        v4_obj->Msg_0x65_id = v9_dataMsg.id;
    }
    EnterCriticalSection(&g_critSec);
    if (v5_obj) {
        v5_obj->next = g_Obj543D99_list_head;
        g_Obj543D99_list_head = v5_obj;
    }
    Obj543D99 *f0_cur = g_Obj543D99_list_head;
    Obj543D99 *v7_last = NULL;
    while (f0_cur) {
        if (CurrentMs - f0_cur->timeMs < 5000) {
            v7_last = f0_cur;
        } else {
            if (v7_last)
                v7_last->next = f0_cur->next;
            else
                g_Obj543D99_list_head = f0_cur->next;
            dk2::operator_delete(f0_cur);
        }
        f0_cur = g_Obj543D99_list_head;
        if (v7_last)
            f0_cur = v7_last->next;
    }
    LeaveCriticalSection(&g_critSec);
    return 1;
}

void dk2::CFrontEndComponent::sub_543E40(int a2_playersSlot, int a3_Msg_0x65_id) {
    unsigned int CurrentMs = WeaNetR_instance.mldplay->GetCurrentMs();
    EnterCriticalSection(&g_critSec);
    Obj543D99 *v12_last = NULL;
    for (Obj543D99 *v5_cur = g_Obj543D99_list_head; v5_cur; v5_cur = v5_cur->next) {
        if (v5_cur->Msg_0x65_id != a3_Msg_0x65_id) {
            v12_last = v5_cur;
            continue;
        }
        Obj543ECE *pObj = &this->deltaTimeMs_arrx16[a2_playersSlot];
        memcpy(&pObj->deltaTimeMs_arrx16[1],
               &pObj->deltaTimeMs_arrx16[0], 15 * 4);
        pObj->deltaTimeMs_arrx16[0] = CurrentMs - v5_cur->timeMs;
        unsigned int v8_totalTimeMs = 0;
        for (int i = 0; i < 16; ++i) {
            v8_totalTimeMs += pObj->deltaTimeMs_arrx16[i];
        }
        g_MyPlayerConfig_instance_arr[a2_playersSlot].totalTimeMs_shr4 = v8_totalTimeMs >> 4;
        if (v12_last)
            v12_last->next = v5_cur->next;
        else
            g_Obj543D99_list_head = v5_cur->next;
        dk2::operator_delete(v5_cur);
        break;
    }
    LeaveCriticalSection(&g_critSec);
}

char dk2::CFrontEndComponent::createMultiplayerGame() {
    this->sub_548520();
    this->f15 = 0;
    if (!g_mpGameName || !g_mpPlayerName) return 0;
    *(DWORD *) &this->b1_msg6F_start__levelCfg = 0;
    this->b5_kickedPlayerMask = 0;
    uint8_t *MbString = MyMbStringList_idx1091_getMbString(0x1Bu);
    strcpy((char *) this->mbStr, (const char *) MbString);
    memset(g_MyPlayerConfig_instance_arr, 0, sizeof(g_MyPlayerConfig_instance_arr));
    unsigned int v3_playerIdx = 0;
    if (this->playersCount) {
        MyPlayerConfig *p_f3A_flags = &g_MyPlayerConfig_instance_arr[0];
        do {
            uint8_t f3A_flags = (p_f3A_flags++)->flags;
            ++v3_playerIdx;
            *(uint8_t *) &p_f3A_flags[-1].name_or_aiId[0] = f3A_flags & 0xF0;
        } while (v3_playerIdx < this->playersCount);
    }
    unsigned int v12_playerSlot;
    if (!WeaNetR_instance.createSession(g_mpGameName, g_mpPlayerName, &v12_playerSlot, 4))
        return 0;
    MyResources_instance.playerCfg.saveMpName(g_mpPlayerName);
    MyResources_instance.playerCfg.saveMpGameName(g_mpGameName);
    WeaNetR_instance.mldplay->EnableNewPlayers(1);
    this->sub_54EE60(g_mpGameName);
    MyPlayerConfig &playerConfig = g_MyPlayerConfig_instance_arr[v12_playerSlot];
    playerConfig.flags = playerConfig.flags & 0xF8 | 2;
    wcscpy(playerConfig.name_or_aiId, g_mpPlayerName);

    net::MLDPLAY_PLAYERINFO playerinfo;
    memset(&playerinfo, 0, sizeof(playerinfo));
    WeaNetR_instance.mldplay->GetPlayerDesc(&playerinfo, v12_playerSlot);
    playerConfig.playerId = playerinfo.f26_playerId_slot.value;
    playerConfig._physMem_mb = getPhysMemInMb();
    playerConfig.totalTimeMs_shr4 = 0;
    playerConfig.flags = playerConfig.flags & 0xD7 | 0x20;
    this->f325 = 0;
    g__humanPlayersCount = 1;
    g__aiPlayersCount = 0;
    this->timeMs_463 = getTimeMs();
    return 1;
}

char dk2::CFrontEndComponent::joinMultiplayerGame(int a2_playerSlot) {
    FoundSessionDesc v15_foundDesc;
    v15_foundDesc.found = 0;
    v15_foundDesc.desc = NULL;
    this->sub_548520();
    this->f15 = 0;
    *(DWORD * ) &this->b1_msg6F_start__levelCfg = 0;
    this->b5_kickedPlayerMask = 0;
    uint8_t *MbString = MyMbStringList_idx1091_getMbString(0x1Bu);
    strcpy((char *) this->mbStr, (const char *) MbString);
    memset(g_MyPlayerConfig_instance_arr, 0, sizeof(g_MyPlayerConfig_instance_arr));
    unsigned int v4_idx = 0;
    if (this->playersCount) {
        MyPlayerConfig *p_f3A_flags = &g_MyPlayerConfig_instance_arr[0];
        do {
            unsigned __int8 v6_flags = (p_f3A_flags++)->flags;
            ++v4_idx;
            *(uint8_t *) &p_f3A_flags[-1].name_or_aiId[0] = v6_flags & 0xF0;
        } while (v4_idx < this->playersCount);
    }
    v15_foundDesc.found = 1;
    v15_foundDesc.desc = (MLDPLAY_SESSIONDESC *) &((net::MLDPLAY_SESSIONDESC *) g_MLDPLAY_SESSIONDESC_arr)[a2_playerSlot];
    op_delete((void **) &g_mpGameName);
    size_t v7 = wcslen(((net::MLDPLAY_SESSIONDESC *) v15_foundDesc.desc)->gameName);
    wchar_t *v8_sessionName = (wchar_t *) malloc_2(2 * v7 + 2);
    g_mpGameName = v8_sessionName;
    if (!v8_sessionName)
        return 0;
    wcscpy(v8_sessionName, ((net::MLDPLAY_SESSIONDESC *) v15_foundDesc.desc)->gameName);
    unsigned int v14_mpcSlot;
    if (!WeaNetR_instance.joinNetworkSession(&v15_foundDesc, g_mpPlayerName, &v14_mpcSlot))
        return 0;
    MyResources_instance.playerCfg.saveMpName(g_mpPlayerName);
    this->sub_54EE60(g_mpGameName);
    wcscpy(g_MyPlayerConfig_instance_arr[v14_mpcSlot].name_or_aiId, g_mpPlayerName);

    net::MLDPLAY_PLAYERINFO playerinfo;
    memset(&playerinfo, 0, sizeof(playerinfo));
    WeaNetR_instance.mldplay->GetPlayerDesc(&playerinfo, v14_mpcSlot);
    unsigned int v11_mpcSlot = v14_mpcSlot;
    MyPlayerConfig &playerConfig = g_MyPlayerConfig_instance_arr[v11_mpcSlot];
    playerConfig.playerId = playerinfo.f26_playerId_slot.value;
    playerConfig.flags = playerConfig.flags & 0xD8 | 2; // cfg as player
    playerConfig._physMem_mb = getPhysMemInMb();
    playerConfig.totalTimeMs_shr4 = 0;
    playerConfig.flags &= ~8u;
    this->f325 = 0;
    g__humanPlayersCount = 1;
    g__aiPlayersCount = 0;
    this->sub_544530((BYTE *) 1);
    this->timeMs_463 = getTimeMs();
    return 1;
}

void dk2::CFrontEndComponent::sub_542980(FoundPlayService *a2_foundService) {
    DWORD *v3_pos = (DWORD *) this->dwordArr_30D1B;
    int v13_idx = 0;
    memset(this->dwordArr_30D1B, 0, sizeof(this->dwordArr_30D1B));
    net::MyLocalService *f4_service = a2_foundService->service;
    this->f30C1E = 0;
    for (int i = 0; i < f4_service->f10_count; ++i) {
        GUID *f24_pGuid = &f4_service->f24_pGuid[i];
        if(*f24_pGuid == DPAID_INet || *f24_pGuid == DPAID_INetW) {
            *v3_pos = 2;
            ++v13_idx;
            ++v3_pos;
            this->fun_5321A0(11, 3);
            if (wcslen(MyResources_instance.playerCfg.multiplayerName) <= 9) {
                CTextInput *v10_gameName = (CTextInput *) this->findBtnBySomeId(221, 11);
                if (v10_gameName) {
                    if (MyResources_instance.playerCfg.multiplayerName[0])
                        v10_gameName->v_fun_52CA70(MyResources_instance.playerCfg.multiplayerName);
                }
            }
            this->sub_547A00(227, 11);
        } else if (*f24_pGuid == net::BFAID_INet) {
            *v3_pos = 2;
            DWORD *v7_pos = v3_pos + 1;
            *v7_pos = 3;
            v13_idx += 2;
            v3_pos = v7_pos + 1;
            this->fun_5321A0(11, 3);
            if (wcslen(MyResources_instance.playerCfg.multiplayerName) <= 9) {
                CTextInput *gameNameInput = (CTextInput *) this->findBtnBySomeId(221, 11);
                if (gameNameInput) {
                    if (MyResources_instance.playerCfg.multiplayerName[0])
                        gameNameInput->v_fun_52CA70(MyResources_instance.playerCfg.multiplayerName);
                }
            }
            this->sub_547A00(227, 11);
            CTextInput *v9_portInput = (CTextInput *) this->findBtnBySomeId(530, 11);
            if (v9_portInput) {
                wchar_t portBuf[32];
                swprintf(portBuf, L"%lu", 7575);
                v9_portInput->v_fun_52CA70(portBuf);
            }
        }
    }
    this->dwordArr_30D1B[v13_idx] = 7;
    if (this->dwordArr_30D1B[0] == 7) {
        this->dwordArr_30D1B[0] = 6;
        this->dwordArr_30D1B[1] = 7;
        this->fun_5321A0(10, 3);
        if (wcslen(MyResources_instance.playerCfg.multiplayerName) <= 9) {
            CTextInput *v12_mpName = (CTextInput *) this->findBtnBySomeId(204, 10);
            if (v12_mpName) {
                if (MyResources_instance.playerCfg.multiplayerName[0])
                    v12_mpName->v_fun_52CA70(MyResources_instance.playerCfg.multiplayerName);
            }
        }
        this->sub_547A00(230, 10);
    }
}


int dk2::CFrontEndComponent::launchGame() {
    MyInputManagerCb_static_setEnabled(1);
    BYTE levelIdx;
    for (levelIdx = 0; levelIdx < 24; ++levelIdx ) {
        int playerLevelStatus = MyResources_instance.playerCfg.getPlayerLevelStatus(levelIdx + 1);
        if (playerLevelStatus == 0) {
            MyResources_instance.playerCfg.savePlayerLevelStatus(levelIdx + 1, 2);
            break;
        }
        if (playerLevelStatus == 2) break;
    }
    this->key_DIK_SYSRQ = 0;
    MyTextRenderer_instance.f75 = 0;
    this->fun_552C70();
    WeaNetR_instance.reinitializeNetworkSystem();
    MyResources_instance.gameCfg.useFe2d_unk1 = MyResources_instance.gameCfg.useFe2d_unk2 == 1;
    this->isUseFe3d = MyResources_instance.gameCfg.useFe3d;
    MyWindow_instance.recreateOnPrepare = 0;
    uint32_t screenWidth = 640u;
    uint32_t screenHeight = 480u;
    patch::screen_resolution::patchMenuWindowResolution(screenWidth, screenHeight);
    if (!MyWindow_instance.prepareScreenEx(
               screenWidth, screenHeight,
               MyResources_instance.video_settings.display_bitnes,
               MyResources_instance.video_settings.isWindowed,
               this->isUseFe3d != 1,
               this->isUseFe3d == 1
               )) return 0;
    this->pMyDdSurfaceEx = MyWindow_instance.getCurOffScreenSurf();

    int status;
    if(patch::opengl_patch::enabled) {
        // fill with black
        patch::opengl_patch::fillWithColor(*MyWindow_instance.getCurOffScreenSurf(), NULL, Bgraf {0, 0, 0, 0, 0});
        patch::opengl_patch::fillWithColor(g_primarySurf, NULL, Bgraf {0, 0, 0, 0, 0});
    } else {
        MyDdSurfaceEx_fillWithColor(
                &status, MyWindow_instance.getCurOffScreenSurf(), NULL,
                Bgraf {0, 0, 0, 0xFF, 0}, 0
        );
        MyDdSurfaceEx_fillWithColor(
                &status,
                &g_primarySurf,  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
                NULL,
                Bgraf {0, 0, 0, 0xFF, 0}, 0
        );
        Sleep(50u);
    }
    if (!is_welcome_shown) {
        this->showTitleScreen();
        MCI_OPEN_PARMS openParams;
        openParams.dwCallback = 0;
        openParams.wDeviceID = 0;
        openParams.lpstrAlias = NULL;
        openParams.lpstrDeviceType = "cdaudio";
        openParams.lpstrElementName = "E:";
        if (!mciSendCommandA(0, MCI_OPEN, 0x2302u, (DWORD_PTR) &openParams)) {
            mciSendCommandA(0, MCI_OPEN, 0x2302u, (DWORD_PTR) &openParams);
            MCI_GENERIC_PARMS genericParams;
            genericParams.dwCallback = 0;
            mciSendCommandA(openParams.wDeviceID, MCI_CLOSE, 2u, (DWORD_PTR) &genericParams);
        }
        this->showBullfrogIntro();
        this->showIntro();
        is_welcome_shown = 1;
    }
    CWorld_instance.showLoadingScreen();
    CWorld_instance.releaseLoadingScreenSurface();
    RECT v16_rect{12, 435, 201, 473};

    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::fillWithColor(*MyWindow_instance.getCurOffScreenSurf(), &v16_rect, Bgraf {0, 0, 0, 0, 0});
        patch::opengl_patch::fillWithColor(g_primarySurf, &v16_rect, Bgraf {0, 0, 0, 0, 0});
    } else {
        MyDdSurfaceEx_fillWithColor(
                &status, MyWindow_instance.getCurOffScreenSurf(), &v16_rect,
                Bgraf {0, 0, 0, 0xFF, 0}, 0
        );
        MyDdSurfaceEx_fillWithColor(
                &status,
                &g_primarySurf,  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
                &v16_rect,
                Bgraf {0, 0, 0, 0xFF, 0}, 0
        );
    }
    g_flags_74034C = g_flags_74034C & ~0x80;
    this->sub_533E90();
    *(DWORD *)&this->f6701 = 0;
    *(DWORD *)&this->f6705 = 0;
    *(DWORD *)&this->f6709 = 0;
    *(DWORD *)&this->f670D = 0;
    this->poolValue_p2_creatures = NULL;
    this->availability_p3_traps = NULL;
    this->availability_p4_rooms = NULL;
    this->availability_p5_spells = NULL;
    this->availability_p6_doors = NULL;
    g_CFrontEndComponent_ptr = this;
    this->_levelCfgWasBuild = 0;
    this->f30C1E = 0;
    this->f30C1A = 0;
    g_flags_74034C = 0;
    this->f30D90 = 0;
    this->load();
    this->getHighscores();
    this->sub_53E0B0();
    this->sub_53DB30();
    for (int i = 0; i < 11; ++i) {
        CListBox_ItemHeightCfg *pItemHeightCfg = &g_CListBox_itemHeights[i];
        int f0_btnId = pItemHeightCfg->btnId;
        CWindow *window = this->cgui_manager.findGameWindowById(pItemHeightCfg->winId);
        for (CButton *curBtn = window->f66_buttons; curBtn; curBtn = curBtn->f78_next) {
            if (curBtn->f70_id != f0_btnId) continue;
            ((CListBox *) curBtn)->itemHeight = pItemHeightCfg->itemHeight;
            break;
        }
    }
    this->sub_542570();
    if ( this->mapName[0] ) {
        int v13_mapCount = calcMapCount2();
        for (this->lobbySelectedMapIdx = 0; this->lobbySelectedMapIdx < v13_mapCount; this->lobbySelectedMapIdx++) {
            if (_wcsicmp(this->mapInfoArr[this->lobbySelectedMapIdx].name, this->mapName) == 0 ) break;
        }
    }
    this->sub_534F70();
    this->Shots_ddSurfArr_isLoaded[0] = 0;
    this->Shots_ddSurfArr_isLoaded[1] = 0;
    initStringLists();
    CFrontEndComponent_renderButtonsText_38_13_5(this);
    this->sub_53B3D0();
    this->timestampMs = getTimeMs();
    this->usingIme = 0;
    return 1;
}

namespace dk2 {


    MyMapInfo *findMap(CFrontEndComponent *front, SessionMapInfo *mapInfo) {
        for (int i = 0; i < front->mapsCount; ++i) {
            MyMapInfo &curMapInfo = front->mapInfoArr[i];
            if (curMapInfo.nameHash != mapInfo->nameHash) continue;
            if (wcslen(curMapInfo.name) != mapInfo->nameLen) continue;
            return &curMapInfo;
        }
        return nullptr;
    }


}

char dk2::CFrontEndComponent::updateNetworkSessions() {
    unsigned int v2_netstatus = WeaNetR_instance.enumerateSessions(TRUE);
    unsigned __int8 *MbString;
    if ( v2_netstatus > 0x20 ) {
        if ( v2_netstatus != 0x40000 )
            return 1;
        MbString = MyMbStringList_idx1091_getMbString(0x823u);
        strcpy((char *) this->mbStr, (const char *)MbString);
        return 1;
    }
    if (v2_netstatus == 32) return 0;
    if (v2_netstatus == 1) {
        MbString = MyMbStringList_idx1091_getMbString(0x816u);
        strcpy((char *) this->mbStr, (const char *)MbString);
        return 1;
    }
    if (v2_netstatus != 2) return 1;
    op_delete((void **)&g_networkStrInfo);
    wchar_t *networkStrInfo = (wchar_t *) malloc_2(2u);
    g_networkStrInfo = networkStrInfo;
    if (!networkStrInfo) return 0;
    *networkStrInfo = '\0';
    memset(this->isSessionCompatible, 0, 8);
    sub_54E4D0();
    if ( g_MLDPLAY_SESSIONDESC_arr_count ) {
        if (CButton *btn = this->findBtnBySomeId(577, 39)) btn->f5D_isVisible = 1;
        if (CButton *btn = this->findBtnBySomeId(224, 11)) btn->f5D_isVisible = 1;
        if (CButton *btn = this->findBtnBySomeId(207, 10)) btn->f5D_isVisible = 1;
    } else {
        if (CButton *btn = this->findBtnBySomeId(577, 39)) btn->f5D_isVisible = 0;
        if (CButton *btn = this->findBtnBySomeId(224, 11)) btn->f5D_isVisible = 0;
        if (CButton *btn = this->findBtnBySomeId(207, 10)) btn->f5D_isVisible = 0;
    }
    unsigned int curSize = 2;
    for (int i = 0; i < g_MLDPLAY_SESSIONDESC_arr_count; ++i) {
        auto &sessionDesc = g_MLDPLAY_SESSIONDESC_arr[i];
        SessionMapInfo mapInfo = sessionDesc.mapInfo;
        int v13_aiPlayersCount = mapInfo.aiPlayersCount_flag & 0x7F;
        unsigned int v14_mapPlayersCount = mapInfo.playersCount;
        wchar_t incompatibleReason[128];
        if (patch::display_incompatible_reason::enabled) {
            wcscpy(incompatibleReason, L"#");
        }
        unsigned int majorVersion = (sessionDesc.gameVersion >> 16) & 0xFFFF;
        wchar_t versionStr[64];
        if ( majorVersion ) {
            int minorVersion = sessionDesc.gameVersion & 0xFFFF;
            swprintf(versionStr, L"#%lu.%lu", majorVersion, minorVersion);
        } else {
            unsigned __int8 *v18 = MyMbStringList_idx1091_getMbString(0xBCCu);
            wchar_t Format[32];
            MBToUni_convert(v18, Format, 32);
            swprintf(versionStr, L"#%s", Format);
        }
        g_currentPlayersInSession = v13_aiPlayersCount + sessionDesc.currentPlayers;
        // patch::log::dbg("compatible: hasSlots=%d<%d version=%X?%X hash=%08X?%08X notSingleplayer=%d>1",
        //     g_currentPlayersInSession, v14_mapPlayersCount,
        //     (g_minorVersion | (g_majorVersion << 16)), sessionDesc.gameVersion,
        //     sessionDesc.fileHashsum, g_fileHashsum,
        //     v14_mapPlayersCount > 1
        // );
        int gameVersion = g_minorVersion | (g_majorVersion << 16);

        bool isCompatible = true;

        wchar_t mapNameStr[64];
        // this->isMapPresent(&mapInfo, mapNameStr);
        {  // inlined this->isMapPresent
            if (auto *info = findMap(this, &mapInfo)) {
                wcscpy(mapNameStr, info->name);
            } else {
                wchar_t name[60];
                MBToUni_convert(MyMbStringList_idx1091_getMbString(0xC06u), name, 50);
                wcscpy(mapNameStr, name);
                if (patch::display_incompatible_reason::enabled) {
                    wsprintfW(incompatibleReason, L"#missing map hash:%X len:%d", mapInfo.nameHash, mapInfo.nameLen);
                    isCompatible = false;
                }
            }
        }

        if (g_currentPlayersInSession >= v14_mapPlayersCount) {
            isCompatible = false;
            if (patch::display_incompatible_reason::enabled) {
                wcscpy(incompatibleReason, L"#room is full");
            }
        } else if (sessionDesc.gameVersion != gameVersion) {
            isCompatible = false;
            if (patch::display_incompatible_reason::enabled) {
                wsprintfW(incompatibleReason, L"#bad exe version %08X != cur:%08X", sessionDesc.gameVersion, gameVersion);
            }
        } else if (sessionDesc.fileHashsum != g_fileHashsum) {
            isCompatible = false;
            if (patch::display_incompatible_reason::enabled) {
                wsprintfW(incompatibleReason, L"#bad exe hashsum %08X != cur:%08X", sessionDesc.fileHashsum, g_fileHashsum);
            }
        } else if (v14_mapPlayersCount <= 1) {
            isCompatible = false;
            if (patch::display_incompatible_reason::enabled) {
                wcscpy(incompatibleReason, L"#maxPlayers <= 1");
            }
        }
        this->isSessionCompatible[i] = isCompatible;
        if (v14_mapPlayersCount == 0) v14_mapPlayersCount = 4;
        wchar_t playerCountsStr[128];
        swprintf(playerCountsStr, L"#%lu / %lu#", g_currentPlayersInSession, v14_mapPlayersCount);
        size_t newSize = sizeof(wchar_t) * (
            wcslen(sessionDesc.sessionName) + wcslen(playerCountsStr) + wcslen(mapNameStr) + wcslen(versionStr)
        ) + 2 + curSize;
        if (patch::display_incompatible_reason::enabled) {
            newSize += sizeof(wchar_t) * wcslen(incompatibleReason);
        }
        wchar_t *newStrInfoBuf = (wchar_t *) realloc_soft(g_networkStrInfo, curSize, newSize);
        if (!newStrInfoBuf) {
            g_networkStrInfo[(curSize - 1) >> 1] = -1;
            netStrLen((__int16 *)g_networkStrInfo);
            return 0;
        }
        g_networkStrInfo = newStrInfoBuf;
        curSize = newSize;
        wcscat(g_networkStrInfo, sessionDesc.sessionName);
        wcscat(g_networkStrInfo, playerCountsStr);
        wcscat(g_networkStrInfo, mapNameStr);
        wcscat(g_networkStrInfo, versionStr);
        if (patch::display_incompatible_reason::enabled) {
            wcscat(g_networkStrInfo, incompatibleReason);
        }
        wcscat(g_networkStrInfo, g_sessionStrInfoSeparator);
    }
    g_networkStrInfo[(curSize - 1) >> 1] = -1;
    netStrLen((__int16 *)g_networkStrInfo);
    patch::auto_network::onSessionsUpdated(this);
    return 1;
}

void dk2::CFrontEndComponent::isMapPresent(SessionMapInfo *mapInfo, wchar_t *mapName) {
    if (auto *info = findMap(this, mapInfo)) {
        wcscpy(mapName, info->name);
    } else {
        wchar_t name[60];
        MBToUni_convert(MyMbStringList_idx1091_getMbString(0xC06u), name, 50);
        wcscpy(mapName, name);
    }
}

void dk2::CFrontEndComponent::showMovie(LPSTR pszFileName) {
    int status;
    if (MyWindow_instance.isWindowed || !MyResources_instance.gameCfg.showMovies) return;

    MyWindow_sub_559770((__int16) &MyWindow_instance);
    this->fun_536E20(0, 0);
    MyDdSurfaceEx_fillWithColor(
        &status, MyWindow_instance.getCurOffScreenSurf(), NULL,
        Bgraf {0, 0, 0, 0xFF, 0}, 0
    );
    MyDdSurfaceEx_fillWithColor(
        &status,
        &g_primarySurf,  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200
        NULL,
        Bgraf {0, 0, 0, 0xFF, 0}, 0
    );
    Sleep(50u);
    memset(&MovieRenderer_instance, 0, sizeof(MovieRenderer_instance));
    MovieRenderer_instance.flags4 = 0xB05064C;
    MovieRenderer_instance.flags8 = 7;

    {
        char sysCmdBuf[sizeof(TbSysCommand_StopAll)];
        auto& sysCmd = *(TbSysCommand_StopAll*) sysCmdBuf;
        *(void**) &sysCmd = TbSysCommand_StopAll::vftable;
        g_MySound_ptr->v_fun_567A40(&status, &sysCmd);
    }

    IDirectSound* v13_pDirectSound = NULL;
    {
        char sysCmdBuf[sizeof(TbSysCommand_GetDirectSoundObject)];
        auto& sysCmd = *(TbSysCommand_GetDirectSoundObject*) sysCmdBuf;
        *(void**) &sysCmd = TbSysCommand_GetDirectSoundObject::vftable;
        sysCmd.ppDirectSound = &v13_pDirectSound;
        g_MySound_ptr->v_fun_567A40(&status, &sysCmd);
    }

    if (v13_pDirectSound) {
        MovieRenderer_instance.directSound = v13_pDirectSound;
        MovieRenderer_instance.flags4 |= 0xA00000u;
    } else {
        MovieRenderer_instance.directSound = NULL;
        MovieRenderer_instance.flags4 |= 0x800000u;
    }
    MovieRenderer_instance.pFun = (int) sub_53C2C0;
    MovieRenderer_instance.lpdd = ge_dk2dd_get(1);
    MovieRenderer_instance.lpdd2 = NULL;
    MovieRenderer_instance.obj_58 = 0;
    MovieRenderer_instance.soundBuffer = NULL;
    int v14 = MyWindow_instance.f18;
    if ((MyWindow_instance.f18 & 1) != 0) {
        copyToFullscreenSurf(&status, 0);
        MyWindow_instance.f18 = v14 + 1;
    }
    {
        LPDIRECTDRAWSURFACE lpDdSurf = MyDdSurface_addRef(&g_primarySurf.dd_surf, 1);
        lpDdSurf->QueryInterface(CLSID_IDirectDrawSurface2, (LPVOID*) &MovieRenderer_instance.p_primarySurf);
        lpDdSurf->Release();
    }
    {
        LPDIRECTDRAWSURFACE lpDdSurf = MyDdSurface_addRef(&g_pCurOffScreen->dd_surf, 1);
        lpDdSurf->QueryInterface(CLSID_IDirectDrawSurface2, (LPVOID*) &MovieRenderer_instance.p_offScreenSurf);
        lpDdSurf->Release();
    }
    g_pMovieRenderer = NULL;
    MyWindow_instance.addWmActivateCallback(CFrontEndComponent_WM_ACTIVATE_cb, this);
    g_pMovieRenderer = static_MovieRenderer_sub_5A8F70(pszFileName, getHWindow(), &MovieRenderer_instance);
    if (g_pMovieRenderer) {
        while (static_MovieRenderer_sub_5A8FB0(g_pMovieRenderer)) {
            MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                &CFrontEndComponent_MovieRenderer_static_listeners, 0, NULL, 0
            );
            Sleep(50u);
        }
        g_movieKeyActed = 0;
        g_pMovieRenderer = NULL;
    }
    MyWindow_instance.removeWmActivateCallback(CFrontEndComponent_WM_ACTIVATE_cb);
    MovieRenderer_instance.lpdd->Release();
    MovieRenderer_instance.p_primarySurf->Release();
    MovieRenderer_instance.p_offScreenSurf->Release();
    MyDdSurfaceEx_fillWithColor(
        &status, MyWindow_instance.getCurOffScreenSurf(), NULL,
        Bgraf {0, 0, 0, 0xFF, 0}, 0
    );
    MyDdSurfaceEx_fillWithColor(
        &status,
        &g_primarySurf,  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
        NULL,
        Bgraf {0, 0, 0, 0xFF, 0}, 0
    );
    this->fun_536E20(1, 0);
    this->timestampMs = getTimeMs();
}

void dk2::CFrontEndComponent::TcpIpInternet_updateStatusLine(unsigned int a1) {
    if (MyWindow_instance.isWindowed != 0) return;
    MyDdSurfaceEx *PrimarySurf = &g_primarySurf; // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
    int status;
    if (*MyDdSurfaceEx_lock(&status, PrimarySurf, 0) >= 0) {
        unsigned __int8 *MbString = MyMbStringList_idx1091_getMbString(a1);
        strcpy((char *) this->mbStr, (const char *) MbString);
        CButton *foundButton = NULL;
        for (
                CButton *f66_buttons = this->cgui_manager.findGameWindowById(11)->f66_buttons;
                f66_buttons; f66_buttons = f66_buttons->f78_next) { // tcpip internet / status line
            if (f66_buttons->f70_id != 532) continue;
            foundButton = f66_buttons;
            break;
        }
        MySurface a1_surf;
        a1_surf.constructor_empty();
        MySurface *v7_surf = g_MyNBitTexture_myRenderSurface;
        MyDdSurfaceEx *v8_primSurf = &g_primarySurf;  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
        MySurface_copyFromSurf(&a1_surf, v8_primSurf);
        MyNBitTexture_initWithSurf(&a1_surf);
        AABB v11_aabb;
        foundButton->getScreenAABB(&v11_aabb);
        AABB v12_aabb;
        v11_aabb = *this->cgui_manager.scaleAabb_2560_1920(&v12_aabb, &v11_aabb);
        MyNBitTexture_fC(&v11_aabb, this->color30319);
        CButton_render_546150(foundButton, this);
        MyNBitTexture_initWithSurf(v7_surf);
        MyDdSurfaceEx *v9 = &g_primarySurf;  // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
        MyDdSurfaceEx_unlock(v9);
    }
}

int __cdecl dk2::CFrontEndComponent_onKeyboardActionWithCtrl(
        int keyCode,
        int isPressed,
        unsigned int controlKeyFlags,
        CFrontEndComponent *frontend) {
    frontend->timestampMs = getTimeMs();
    if (!isPressed) return 1;

    if (controlKeyFlags == 3 && keyCode == 0x20) {  // DIK_D
        const char *PacketRecordStr = getPacketRecordStr();
        char Buffer[260];
        sprintf(Buffer, "%s\\%s.sav", PacketRecordStr, "DemoLoad");
        if (fs_fileExists(Buffer)) {
            MyResources_instance.packetRecord.loadSavFile("DemoLoad", 1, 0);
            if (frontend->isUseFe3d)
                MyResources_instance.gameCfg.unk_f16C = 1;
            frontend->gotoComponent(&CGameComponent_instance);
        }
    }
    if (keyCode == 0xB7)                        // DIK_SYSRQ
        frontend->key_DIK_SYSRQ = 1;
    if (frontend->f30C1A) {
        updateKeyBind(keyCode, controlKeyFlags, frontend);
        return 1;
    }
    if (keyCode == 0x1C && controlKeyFlags == 2)// DIK_RETURN
        MyWindow_instance.prepareScreen2();
    return 1;
}

dk2::NameCfg *dk2::CFrontEndComponent::sub_535A30() {
    this->f5AE1 = 0;
    this->f5B05 = 0;
    this->f5ADD = 0;
    this->f5AD1 = 0;
    this->f5AD9 = 0;
    this->f5AD5 = 0;
    memset(this->f5AE5, 0, sizeof(this->f5AE5));
    this->f5AAD = 0;
    this->f5AB1 = 0;
    this->f5AB5 = 0;
    this->f5AB9 = 0;
    this->f5ABD = 0;
    this->f5AC1 = 0;
    this->f5AC5 = 0;
    this->f5AC9 = 0;
    this->f5ACD = 0;
    this->f5AAD = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OPTIONS_MUSIC");
    this->f5AB1 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OPTIONS_SPEECH");
    this->f5AC5 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "ONE_SHOT_ATMOS");
    this->f5AC9 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "MUSIC");
    this->f5AB9 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "FRONT_END");
    this->f5AB5 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OBJECT_FE_MAP");
    this->f5ABD = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OBJECT_FE_WINDOW");
    this->f5ACD = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OBJECT_FE_PENDULUM");
    this->f5AC1 = g_MySound_ptr->v_fun_567790("GLOBAL\\", "OBJECT_FE_PARCHMENT");
    NameCfg *result = g_soundNameList;
    if (g_soundNameList[0].idx != -1) {
        int next_idx;
        do {
            int idx = result->idx;
            if (result->idx >= 27 && idx <= 36) {
                if (idx == 32)
                    result->f24 = this->f5AB9;
                else
                    result->f24 = this->f5AC1;
            }
            next_idx = result[1].idx;
            ++result;
        } while (next_idx != -1);
    }
    return result;
}

int dk2::CFrontEndComponent::fun_53EF60(unsigned __int8 a2_min, unsigned __int8 a3_max) {
    if (!this->mapsCount) return 0;

    if(patch::default_map::enabled) {
        this->lobbySelectedMapIdx = patch::default_map::getPreselectedMapIdx(this);
        if(this->lobbySelectedMapIdx != -1) {
            this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
            return 1;
        }
    }

    {
        // select random map
        DWORD TimeMs = getTimeMs();
        this->lobbySelectedMapIdx = -1;
        for(unsigned int v5 = 0; v5 < 2 * this->mapsCount; ++v5) {
            TimeMs = 1664525 * TimeMs + 0x3C6EF35F;
            unsigned int a2_mina = std::rotr(TimeMs, 13);
            MyMapInfo *f657C_mapInfoArr = this->mapInfoArr;
            this->lobbySelectedMapIdx = a2_mina % this->mapsCount;
            MyMapInfo *pMapInfo = &f657C_mapInfoArr[a2_mina % this->mapsCount];
            if (pMapInfo->playerCount >= a2_min && pMapInfo->playerCount <= a3_max && (pMapInfo->eos & 1) != 0) break;
        }
        if (this->lobbySelectedMapIdx != -1) {
            this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
            return 1;
        }
    }

    // select first compatible map
    this->lobbySelectedMapIdx = -1;
    for (unsigned int v11_idx = 0; v11_idx < this->mapsCount; ++v11_idx) {
        MyMapInfo *v12_inf = &this->mapInfoArr[v11_idx];
        if (v12_inf->playerCount < a2_min) continue;
        if (v12_inf->playerCount > (unsigned int) a3_max) continue;
        if ((v12_inf->eos & 1) == 0) continue;
        this->lobbySelectedMapIdx = v11_idx;
        break;
    }
    this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
    return 1;
}

int __cdecl dk2::CButton_handleLeftClick_5463B0(int a1, int a2, CFrontEndComponent *a3) {
    unsigned __int8 v5 = 2;
    if (g__humanPlayersCount + g__aiPlayersCount > 2)
        v5 = g__humanPlayersCount + g__aiPlayersCount;
    int result = a3->fun_53EF60(v5, a3->playersCount);
    if (result != 1)
        return result;
    wchar_t *MapName = a3->getMapName();
    return a3->loadMapThumbnail(MapName);
}

int dk2::CFrontEndComponent::randomizeMap(unsigned __int8 a2_minPlayersCount, unsigned __int8 a3_maxPlayersCount) {
    if (!this->mapsCount) return 0;

    if(patch::default_map::enabled) {
        this->lobbySelectedMapIdx = patch::default_map::getPreselectedMapIdx(this);
        if(this->lobbySelectedMapIdx != -1) {
            this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
            return 1;
        }
    }

    {
        // select random map
        DWORD TimeMs = getTimeMs();
        this->lobbySelectedMapIdx = -1;
        for (unsigned int v5_tryIdx = 0; v5_tryIdx < 2 * this->mapsCount; ++v5_tryIdx) {
            TimeMs = 0x19660D * TimeMs + 0x3C6EF35F;
            unsigned int v16_randomInt = std::rotr(TimeMs, 13);
            this->lobbySelectedMapIdx = v16_randomInt % this->mapsCount;
            MyMapInfo *pMapInfo = &this->mapInfoArr[v16_randomInt % this->mapsCount];
            if (pMapInfo->playerCount >= a2_minPlayersCount && pMapInfo->playerCount <= a3_maxPlayersCount && (pMapInfo->eos & 2) != 0) break;
        }
        if (this->lobbySelectedMapIdx != -1) {
            this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
            return 1;
        }
    }

    // select first compatible map
    this->lobbySelectedMapIdx = -1;
    for(unsigned int v11_mapIdx = 0; v11_mapIdx < this->mapsCount; ++v11_mapIdx) {
        MyMapInfo *mapInfo = &this->mapInfoArr[v11_mapIdx];
        if (mapInfo->playerCount < a2_minPlayersCount) continue;
        if (mapInfo->playerCount > (unsigned int) a3_maxPlayersCount) continue;
        if ((mapInfo->eos & 2) == 0) continue;
        this->lobbySelectedMapIdx = v11_mapIdx;
        break;
    }
    this->lobbyMapWasChanged(this->lobbySelectedMapIdx);
    return 1;
}

int __cdecl dk2::CButton_handleLeftClick_randomMap(int a1, int a2, CFrontEndComponent *a3_front) {
    unsigned __int8 v5 = 2;
    if ( g__humanPlayersCount + g__aiPlayersCount > 2 )
        v5 = g__humanPlayersCount + g__aiPlayersCount;
    int result = a3_front->randomizeMap(v5, a3_front->playersCount);
    if ( result != 1 )
        return result;
    wchar_t *MapName = a3_front->getMapName();
    return a3_front->loadMapThumbnail(MapName);
}


int dk2::CFrontEndComponent::draw2dGui_0() {
    this->pMyDdSurfaceEx = MyWindow_instance.getCurOffScreenSurf();
    MyWindow_instance.getMousePos();
    if (MyWindow_instance.getSurf_lock() != 0) {
        MySurface surf;
        this->surf65_btnRenderOut = *surf.copySurfFrom(this->pMyDdSurfaceEx);
        this->cgui_manager.doDraw2dGui(this);
        CWindow *GameWindowById = this->cgui_manager.findGameWindowById(47);
        if (this->usingIme == 1 && GameWindowById->f44_isCurrent == 1)
            CButton_sub_547C20(GameWindowById->f66_buttons, this);
        MyWindow_instance.getSurf_unlock();
    }
    return 1;
}

int dk2::CFrontEndComponent::draw2dGui() {
    return this->draw2dGui_0();
}

