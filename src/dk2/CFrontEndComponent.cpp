//
// Created by DiaLight on 21.07.2024.
//
#include <dk2/CFrontEndComponent.h>
#include <dk2/Obj543D99.h>
#include <dk2/NetMessage_65.h>
#include <dk2/network/FoundSessionDesc.h>
#include <dk2/button/CTextInput.h>
#include <weanetr_dll/MLDPlay.h>
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"
#include "dk2_memory.h"
#include "weanetr_dll/globals.h"
#include "patches/logging.h"


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
        MyGame_instance.prepareScreen();
        if ( MyDdSurface_addRef(&this->titleScreen.dd_surf, 0) )
            MyDdSurface_release(&status, &this->titleScreen.dd_surf);

        if(!patch::skippable_title_screen::enabled) {
            DWORD waitEnd = getTimeMs() + 10000;
            while ( getTimeMs() <= waitEnd ) ;
        } else {
            DWORD waitEnd = getTimeMs() + patch::skippable_title_screen::waiting_time;
            while ( getTimeMs() <= waitEnd && !patch::skippable_title_screen::skipKeyPressed() ) ;
        }
        MyGame_instance.prepareScreen();
    }
}

char dk2::CFrontEndComponent::sub_5435E0(int a2, CFrontEndComponent *a3_comp) {
    if (!g_networkIsHost_740360) return 1;
    if (!WeaNetR_instance.updatePlayers_isHost()) return 1;

    size_t v5_netDataLen = 2 * wcslen(g_networkData_0073FB90) + 2;
    unsigned int v22_p2_sz = 5 * a3_comp->msg6F_p2_sz;
    unsigned int v24_p3_sz = 5 * a3_comp->msg6F_p3_sz;
    unsigned int v23_p4_sz = 5 * a3_comp->msg6F_p4_sz;
    unsigned int v21_p5_sz = 5 * a3_comp->msg6F_p5_sz;
    unsigned int v25_p6_sz = 5 * a3_comp->msg6F_p6_sz;
    size_t v6_bufSize = v22_p2_sz + v24_p3_sz + v23_p4_sz + v21_p5_sz + v25_p6_sz + v5_netDataLen + 22;
    unsigned int v26_bufSize = v6_bufSize;
    BYTE *v7_buf = (BYTE *) malloc_2(v6_bufSize);
    if (!v7_buf) return 0;

    memset(v7_buf, 0, v6_bufSize);
    *v7_buf = 0xC7;
    wcscpy((wchar_t *) (v7_buf + 1), g_networkData_0073FB90);
    BYTE *v8_header = &v7_buf[v5_netDataLen + 1];
    *(DWORD *) v8_header = *(DWORD *) &this->msg6F_start;
    v8_header[4] = this->msg6F_p1;

    memcpy(&v7_buf[v5_netDataLen + 6], this->msg6F_p2, v22_p2_sz);

    unsigned int v9_p3_offs = v22_p2_sz + v5_netDataLen + 6;
    memcpy(&v7_buf[v9_p3_offs], this->msg6F_p3, v24_p3_sz);

    unsigned int v10_p4_offs = v24_p3_sz + v9_p3_offs;
    memcpy(&v7_buf[v10_p4_offs], this->msg6F_p4, v23_p4_sz);

    unsigned int v11_p5_offs = v23_p4_sz + v10_p4_offs;
    memcpy(&v7_buf[v11_p5_offs], this->msg6F_p5, v21_p5_sz);

    unsigned int v12_p6_offs = v21_p5_sz + v11_p5_offs;
    memcpy(&v7_buf[v12_p6_offs], this->msg6F_p6, v25_p6_sz);

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
// function with bug

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
            if ((((unsigned __int8) this->msg6F_p1 >> v13_n) & 1) == 1) {
                if (p_f26_playerId->f26_playerId_slot == v14_playerInfo->f26_playerId_slot)
                    this->sub_5455A0(v13_n);
                else
                    this->msg6F_p1 &= ~(1 << v13_n);
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
    *(DWORD *) &this->msg6F_start = 0;
    this->msg6F_p1 = 0;
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
    MyResources_instance.playerCfg.setMpName(g_mpPlayerName);
    MyResources_instance.playerCfg.setMpGameName(g_mpGameName);
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
    *(DWORD * ) &this->msg6F_start = 0;
    this->msg6F_p1 = 0;
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
    MyResources_instance.playerCfg.setMpName(g_mpPlayerName);
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

