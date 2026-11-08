//
// Created by DiaLight on 2/4/2026.
//

#include "dk2_globals.h"
#include "dk2_functions.h"
#include "dk2_memory.h"
#include "dk2/sound/TbSysCommand_Process.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/MyFoundThingResult.h"
#include "math/q12_utils.h"


int dk2::MyGameSession::tick(int a2_isNeedBlt) {
    int try_level;

    Vec3q12 actionLoc = Q12_encode(0, 0, 0);
    if (this->pBridge) {
        CCamera *cam = this->pBridge->v_fD0_getCamera();
        actionLoc = cam->location + cam->locationOffset;
    }
    g_MySound_ptr->v_sub_567290((uint32_t *) &actionLoc);
    if (MyResources_instance.gameCfg.useFe2d_unk1)
        return 1;
    CDefaultPlayerInterface *fC_player_i = this->pPlayer;
    if (fC_player_i) {
        int result = fC_player_i->v_fun_4039A0(a2_isNeedBlt);
        if (!result)
            return result;
    }
    if (!a2_isNeedBlt) {
        if (CCommunicationInterface *communication = this->pCommunication) {
            if (!communication->v_f38())
                return 1;
        }
    }
    this->handleActions();
    if (this->pCommunication) {
        GameActionCtx actions;
        memset(&actions, 0, sizeof(GameActionCtx));
        for_each_construct<GameAction, true>(actions.actionArr, 16);
        Vec3q12 v70 = Q12_encode(0, 0, 0);
        try_level = 0;
        int v71 = 0;
        while (this->pCommunication->v_collectActions(&actions)) {
            DWORD f284_inMenu = this->inMenu;
            if (this->pBridge) {
                CCamera *cam = this->pBridge->v_fD0_getCamera();
                Vec3q12 pos = cam->location + cam->locationOffset;
                v70 = pos;
            }
            MyResources_instance.packetRecord.write(&actions, (uint32_t *) &v70);
            if (MyResources_instance.gameCfg.useFe_playMode == 1
                && MyResources_instance.packetRecord.state == 2
                && MyResources_instance.packetRecord.pUseCamera
                && this->pBridge
                && !v71) {
                CDefaultPlayerInterface *v12_plif = this->pPlayer;
                v71 = 1;
                unsigned __int16 f8_playerTagId = v12_plif->playerTagId;
                GameAction v76;
                v76.data1 = MyResources_instance.packetRecord.f128;
                v76.data2 = MyResources_instance.packetRecord.f12C;
                v76.data3 = MyResources_instance.packetRecord.f130;
                v76.actionKind = 2;
                v76.playerTagId = f8_playerTagId;
                try_level = 1;
                v12_plif->pushAction(&v76);
                try_level = 0;
            }
            if (this->pWorld) {
                void *v74 = &TbSysCommand_Process::vftable;
                int v78_status;
                g_MySound_ptr->v_fun_567A40(&v78_status, &v74);
                if (actions.fF) {
                    unsigned int v44 = this->pWorld->getGameTick();
                    MyWindow_log_printf(&MyWindow_instance, "Need To Resync GT %d\n", v44);
                    if (MyResources_instance.gameCfg.logOos__eos)
                        this->pWorld->v_fun_50EA70();
                    this->gameTick2A2 = this->pWorld->getGameTick();
                    for (unsigned int i = 0; i < actions.actionArr_count; ++i) {
                        GameAction &act = actions.actionArr[i];
                        if (act.actionKind != 117) continue;
                        this->gameTick2A2 = act.data1;
                        break;
                    }
                    CHAR compName[260];
                    memset(compName, 0, sizeof(compName));
                    strcpy(compName, "unknown");
                    DWORD compNameSz = 260;
                    if (this->gameTick28C >= this->gameTick2A2)
                        this->f296 = 1;

                    if (this->f29A) {
                        CWorld *f14_cworld = this->pWorld;
                        int v51 = f14_cworld->v_getMEPlayerTagId();
                        CPlayer *v52 = (CPlayer *) f14_cworld->v_getCTag_508C40(v51);
                        if (v52) {
                            int v53 = v52->playerFlags;
                            v53 |= 0x2000u;
                            v52->playerFlags = v53;
                        }
                        this->pWorld->v_sub_509860(1);
                        try_level = -1;
                        for_each_destruct<GameAction, true>(actions.actionArr, 16);
                        return 0;
                    }
                    if (this->f296) {
                        this->f29A = 1;
                        this->f290 = 1 - this->f290;
                    }
                    GetComputerNameA(compName, &compNameSz);
                    char v83[260];
                    sprintf(
                            v83,
                            "%s%s(%s%d).%s",
                            MyResources_instance.savesDir,
                            pAResync,
                            compName,
                            (unsigned __int16) this->f290 + 1,
                            pANsav);
                    if (!this->pWorld->v_f2C_loadFromFile(v83)) {
                        CWorld *v57 = this->pWorld;
                        int v59 = v57->v_getMEPlayerTagId();
                        CPlayer *v60 = (CPlayer *) v57->v_getCTag_508C40(v59);
                        if (v60) {
                            unsigned int f76_playerFlags = v60->playerFlags;
                            f76_playerFlags |= 0x2000u;
                            v60->playerFlags = f76_playerFlags;
                        }
                        this->pWorld->v_sub_509860(1);
                        try_level = -1;
                        for_each_destruct<GameAction, true>(actions.actionArr, 16);
                        return 0;
                    }
                    // ref: net=00524F50
                    this->pCommunication->v_syncGameTickInit(this->gameTick);
                    this->clickList.reset();
                    CWorld *v54 = this->pWorld;
                    this->isOutOfSync = 0;
                    this->gameTick2A2 = 0;
                    int v55 = v54->getGameTick();
                    this->gameTick28C = v55;
                    this->f296 = 1;
                    this->saveTick288 = v55 + 30 * this->gameTicksPerSecond;
                    break;
                }
                if (actions.f10) {
                    if (MyResources_instance.gameCfg.logOos__eos)
                        this->pWorld->v_fun_50EA70();
                    sprintf(g_temp_string, "GamePacket says we're OOS (GT %d) (Already Logged)", actions.gameTick);
                }
                if (this->isOutOfSync) {
                    unsigned int f2A2_gameTick2A2 = this->gameTick2A2;
                    unsigned int v15 = this->pWorld->getGameTick();
                    MyWindow_log_printf(&MyWindow_instance, "Out Of Sync(on GT %d) GT %d\n", f2A2_gameTick2A2, v15);
                    if (MyResources_instance.packetRecord.state == 2) {
                        unsigned int v16 = this->gameTick2A2;
                        unsigned int v17 = this->pWorld->getGameTick();
                        sprintf(g_temp_string, "Packet Load Out of Sync (on GT %d) GT %d [F10 to Log]\n", v16, v17);
                        if (MyResources_instance.gameCfg.logOos__eos)
                            this->pWorld->v_fun_50EA70();
                    }
                    unsigned int v18 = this->gameTick2A2;
                    unsigned __int16 v19 = this->pWorld->v_getMEPlayerTagId();
                    GameAction v77;
                    v77.data1 = v18;
                    v77.data2 = v18;
                    v77.data3 = 0;
                    v77.actionKind = 117;
                    v77.playerTagId = v19;
                    try_level = 2;
                    this->clickList.add(&v77);
                    try_level = 0;
                } else if (MyResources_instance.useChecksum) {
                    if (actions.fD && actions.tick != this->pWorld->v_sub_509520()) {
                        int v21 = actions.tick;
                        int v65 = this->pWorld->v_sub_509520();
                        unsigned int v62 = this->pWorld->getGameTick();
                        MyWindow_log_printf(&MyWindow_instance, "Gone Out Of Sync (Seed) GT %d [%08X:%08X]\n", v62, v21,
                                            v65);
                        this->isOutOfSync = 1;
                        this->gameTick2A2 = this->pWorld->getGameTick();
                    } else if (MyResources_instance.useChecksum && actions.fE) {
                        int v22_checksum = this->pWorld->v_calcChecksum();
                        if (actions.f9 != v22_checksum) {
                            int v66 = v22_checksum;
                            int v64 = actions.f9;
                            unsigned int v63 = this->pWorld->getGameTick();
                            MyWindow_log_printf(&MyWindow_instance, "Gone Out Of Sync (Checksum) GT %d [%08X:%08X]\n", v63,
                                                v64, v66);
                            this->isOutOfSync = 1;
                            this->gameTick2A2 = this->pWorld->getGameTick();
                        }
                    }
                }
                if (MyResources_instance.gameCfg.useFe_playMode == 3
                    && this->pWorld->getGameTick() > this->saveTick288) {
                    this->gameTick28C = this->pWorld->getGameTick();
                    CHAR Buffer[260];
                    strcpy(Buffer, "unknown");
                    memset(&Buffer[8], 0, 0xFCu);
                    __int16 v24 = 1 - this->f290;
                    DWORD nSize = 260;
                    this->f290 = v24;
                    this->f296 = 0;
                    this->f29A = 0;
                    GetComputerNameA(Buffer, &nSize);
                    char v84[260];
                    sprintf(
                            v84,
                            "%s%s(%s%d).%s",
                            MyResources_instance.savesDir,
                            pAResync,
                            Buffer,
                            (unsigned __int16) this->f290 + 1,
                            pANsav);
                    this->pWorld->v_f28_saveToFile(v84);
                    ++this->f292;
                    this->saveTick288 += 30 * this->gameTicksPerSecond;
                }
                DWORD v25 = getTimeMs();
                unsigned int v26 = this->pWorld->v_tick(&actions);
                unsigned int v27 = getTimeMs() - v25;
                if (v27 > GameSession_worldHighestTickTime)
                    GameSession_worldHighestTickTime = v27;
                if (v27 > 25) {
                    ++GameSession_worldLongFrames_counter;
                    if (g_dword_7962A4) {
                        unsigned int v28 = this->pWorld->getGameTick();
                        MyWindow_log_printf(&MyWindow_instance, "World Frame %d: Took %dms\n", v28, v27);
                    }
                }
                ++GameSession_worldFrames_counter;
                GameSession_worldTickTotalTime += v27;
                GameSession_dword_70D430 += v27;
                ++GameSession_dword_70D458;
                if (GameSession_dword_70D458 == 4) {
                    GameSession_dword_70D44C = GameSession_dword_70D430 >> 2;
                    GameSession_dword_70D430 = 0;
                    GameSession_dword_70D458 = 0;
                }
                g_MySound_ptr->v_fun_5674F0();
                CSpeechSystem_instance.SetMusicVolume(this->inMenu == 0);
                if (!v26) {
                    try_level = -1;
                    for_each_destruct<GameAction, true>(actions.actionArr, 16);
                    return 0;
                }
            }
            if (MyResources_instance.packetRecord.state == 2) {
                int f114_pQuitValue = MyResources_instance.packetRecord.pQuitValue;
                if (f114_pQuitValue == this->pWorld->getGameTick()) {
                    try_level = -1;
                    for_each_destruct<GameAction, true>(actions.actionArr, 16);
                    return 0;
                }
            }
            if (!f284_inMenu || !this->inMenu)
                ++this->gameTick;
            if (MyResources_instance.gameCfg.useFe_playMode == 3) {
                int v67_checksum = this->pWorld->v_calcChecksum();
                unsigned int v33_gameTick = this->pWorld->getGameTick();
                this->pCommunication->v_f1C_sendData_15_WorldChecksum(v33_gameTick, v67_checksum);
                this->timeMs_2A6 = getTimeMs();
            }
        }
        if (this->pWorld->v_sub_509850()) {
            try_level = -1;
            for_each_destruct<GameAction, true>(actions.actionArr, 16);
            return 0;
        }
        if (MyResources_instance.gameCfg.useFe_playMode == 3) {
            unsigned int v34_timeMs = getTimeMs();
            int f2A6_timeMs_2A6 = this->timeMs_2A6;
            if (!f2A6_timeMs_2A6 || f2A6_timeMs_2A6 + 100 < v34_timeMs) {
                int v68_checkSum = this->pWorld->v_calcChecksum();
                unsigned int GameTick = this->pWorld->getGameTick();
                this->pCommunication->v_f1C_sendData_15_WorldChecksum(GameTick, v68_checkSum);
                this->timeMs_2A6 = v34_timeMs;
            }
        }
        try_level = -1;
        for_each_destruct<GameAction, true>(actions.actionArr, 16);
    }
    if (this->pBridge) {
        DWORD TimeMs = getTimeMs();
        CBridge *v39 = this->pBridge;
        DWORD f284_inMenu_ = TimeMs;
        if (v39->v_f38_tryReinit3d()) {
            this->camArgs.gameTick278_last = this->gameTick;
            CCommunicationInterface *v40 = this->pCommunication;
            if (v40) {
                if (!this->inMenu) {
                    unsigned int mspt = 1000u / this->gameTicksPerSecond;
                    this->camArgs.tickPercent256 = (v40->sub_521C80() << 8) / mspt;
                }
            } else {
                this->camArgs.tickPercent256 = 0;
            }
            this->pBridge->v_f2C_updateCameraState(&this->camArgs);
            if (this->pPlayer) {
                if (this->pBridge->v_f40_enableSmth()) {
                    this->pPlayer->v_f14_renderGameMap();
                    int result = this->pBridge->v_f44_disableSmth();
                    if (!result)
                        return result;
                }
            }
            int result = this->pBridge->v_f3C__drawScene();
            if (!result)
                return result;
        }
        DWORD v42 = getTimeMs() - f284_inMenu_;
        if (v42 > GameSession_engineHighestTickTime)
            GameSession_engineHighestTickTime = v42;
        GameSession_engineTickTotalTime += v42;
        DWORD v43 = v42 + GameSession_dword_70D448;
        ++GameSession_engineFrames_counter;
        GameSession_dword_70D448 += v42;
        ++GameSession_dword_70D42C;
        if (GameSession_dword_70D42C == 4) {
            GameSession_dword_70D434 = v43 >> 2;
            GameSession_dword_70D448 = 0;
            GameSession_dword_70D42C = 0;
        }
    }
    return 1;
}
