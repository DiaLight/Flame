//
// Created by DiaLight on 18.01.2025.
//

#include "dk2/CNetworkCommunication.h"
#include "dk2/CWorld.h"
#include "dk2/CDefaultPlayerInterface.h"
#include "dk2/text/textmap/MyMbStringList.h"
#include "dk2/text/TbUniStringVTag.h"
#include "dk2/entities/CPlayer.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/weanetr_dll/MLDPlay.h"
#include "dk2/MySemaphore.h"
#include "dk2/network/protocol/DataMessage_1.h"
#include "dk2_memory.h"


BOOL dk2::CNetworkCommunication::collectActions(GameActionCtx *a2_outCtx) {
    struct _RTL_CRITICAL_SECTION *p_fF504_critSec = &this->critSec;
    int v60_doSendMessage = 0;
    EnterCriticalSection(&this->critSec);
    int var_62C = this->fF51C;
    LeaveCriticalSection(p_fF504_critSec);
    if (var_62C == 1)
        this->v_fun_521B40(1);
    if (!MyResources_instance.networkCfg._eos) {
        DWORD TimeMs = getTimeMs();
        if (WeaNetR_instance.updatePlayers_isHost()) {
            EnterCriticalSection(&this->critSec);
            int v5_timeMs = getTimeMs();
            unsigned int v6_slot = 0;
            struc_250 *p_f20_lastPacket_timeMs = &this->fF744[0];
            do {
                if (WeaNetR_instance.isPlayerJoined(v6_slot)) {
                    if (!p_f20_lastPacket_timeMs->lastPacket_timeMs)
                        p_f20_lastPacket_timeMs->lastPacket_timeMs = v5_timeMs;
                    int v8_timeDelta = v5_timeMs - p_f20_lastPacket_timeMs->lastPacket_timeMs;
                    if (v8_timeDelta < 0)
                        v8_timeDelta = 0;
                    if ((unsigned int) v8_timeDelta > 35000) {
                        MyPlayerInf v53_inf;
                        v53_inf.timeMs = v5_timeMs;
                        v53_inf.state = 3;
                        v53_inf.slot = v6_slot;
                        v53_inf.timeDelta = v8_timeDelta;
                        if (!this->containsPlayerInf(&v53_inf)) {
                            int fF720_playersCount = this->playersCount;
                            if (fF720_playersCount != 32) {
                                this->players[((BYTE) fF720_playersCount + (unsigned __int8) this->playersStart) &
                                              0x1F] = v53_inf;
                                ++this->playersCount;
                            }
                        }
                    }
                }
                ++v6_slot;
                ++p_f20_lastPacket_timeMs;
            } while (v6_slot < 8);
            LeaveCriticalSection(&this->critSec);
        } else {
            if (this->gameActionCtxQueue.totalSize)
                this->case2_timeMs = TimeMs;
            EnterCriticalSection(p_fF504_critSec);
            int v10_timeMs = getTimeMs();
            int v11_timeDelta = v10_timeMs - this->case2_timeMs;
            if (v11_timeDelta < 0)
                v11_timeDelta = 0;
            LeaveCriticalSection(p_fF504_critSec);
            if ((unsigned int) v11_timeDelta > 35000) {
                MyPlayerInf v53_inf;
                v53_inf.timeMs = v10_timeMs;
                v53_inf.state = 6;
                v53_inf.timeDelta = v11_timeDelta;
                if (!this->containsPlayerInf(&v53_inf)) {
                    int v12_playersCount = this->playersCount;
                    if (v12_playersCount != 32) {
                        this->players[((BYTE) v12_playersCount + (BYTE) this->playersStart) & 0x1F] = v53_inf;
                        ++this->playersCount;
                    }
                }
            }
            if ((unsigned int) (v10_timeMs - this->timeMsFDC8) > 1000)
                this->v_f2C();
        }
    }

    while (2) {
        int v13_playersCount = this->playersCount;
        if (v13_playersCount) {
            int fF724_playersStart = this->playersStart;
            MyPlayerInf *v15_inf = &this->players[fF724_playersStart];
            int f0_state = v15_inf->state;
            DWORD f4_timeMs = v15_inf->timeMs;
            unsigned int v19_slot = v15_inf->slot;
            int fC_timeDelta = v15_inf->timeDelta;
            this->playersStart = ((BYTE) fF724_playersStart + 1) & 0x1F;
            int v59_timeDelta = fC_timeDelta;
            this->playersCount = v13_playersCount - 1;
            switch (f0_state) {
                case 0:
                case 4: {
                    CWorld *f14_cworld = this->f0_profiler->cworld;
                    CDefaultPlayerInterface *fC_player_i = f14_cworld->profiler->player_i;
                    uint16_t f0_tagId = f14_cworld->playerList.players_7[v19_slot + 2].f0_tagId;
                    char v53_strVtag_buf[sizeof(TbUniStringVTag)];
                    TbUniStringVTag &v53_strVtag = *(TbUniStringVTag *) v53_strVtag_buf;
                    v53_strVtag.f4 = 1447121485;
                    v53_strVtag.size = 1;
                    CPlayer *v22_player = (CPlayer *) sceneObjects[f0_tagId];
                    *(void **) &v53_strVtag = TbUniStringVTag::vftable;
                    v53_strVtag.value = v22_player->playerName;
                    MyMbStringList *Instance_idx1090 = MyMbStringList_getInstance_idx1090();

                    uint8_t v60_mbBuf[512];
                    MyMbStringList_VTagFormatMB(Instance_idx1090, v60_mbBuf, 512, 1514, &v53_strVtag);
                    wchar_t v61_playerNameBuf[512];
                    MBToUni_convert(v60_mbBuf, v61_playerNameBuf, 512);
                    // append player name to chat
                    fC_player_i->v_fun_409EC0(33667, v61_playerNameBuf);
                }
                    continue;
                case 1:
                case 6: {
                    CWorld *v27_world = this->f0_profiler->cworld;
                    CWorld_instance.fA3C3 = f0_state != 1 ? 2113 : 2077;
                    v27_world->v_sub_509860(1);
                    return 0;
                }
                case 2: {
                    int v24_timeMs = getTimeMs();
                    EnterCriticalSection(&this->critSec);
                    struc_250 *v25_unkPos = &this->fF744[0];
                    int v26_left = 8;
                    do {
                        v25_unkPos->lastPacket_timeMs = v24_timeMs;
                        v25_unkPos++;
                        --v26_left;
                    } while (v26_left);
                    LeaveCriticalSection(&this->critSec);
                    this->case2_timeMs = v24_timeMs;
                }
                    continue;
                case 3:
                case 5:
                    WeaNetR_instance.mldplay->DumpPlayer(v19_slot);  // DestroySession
                    continue;
                default:
                    continue;
            }
        }
        break;
    }

    int v64_try_level;

    if (WeaNetR_instance.updatePlayers_isHost()) {
        int v28_timeMs = getTimeMs();
        if (var_62C == 3) {
            int v29_doProcess = 1;
            EnterCriticalSection(&this->critSec);
            for (unsigned int i = 0; i < 8; ++i) {
                if (WeaNetR_instance.isPlayerJoined(i) && ((1 << i) & this->_playerMask) == 0)
                    v29_doProcess = 0;
            }
            LeaveCriticalSection(&this->critSec);
            if ((unsigned int) (v28_timeMs - this->_timefdd4) <= 15000) {
                if ((unsigned int) (v28_timeMs - this->_timefdd8) > 1000) {
                    int value = this->gameTickF72C;
                    this->sendDataMessage(0x29, &value, 4u, 0xFFFFu);
                    this->_timefdd8 = v28_timeMs;
                }
            } else {
                v29_doProcess = 1;
            }
            if (v29_doProcess) {
                CWorld *v31_world = this->f0_profiler->cworld;
                int v52_aBool = this->fFDF2;
                this->case2_timeMs = v28_timeMs;
                this->_timefdd8 = v28_timeMs;
                this->_timefdd4 = v28_timeMs;
                v31_world->v_fun_510E90(&this->gameAct, v52_aBool);
            }
        }
        EnterCriticalSection(&this->critSec);
        int v32_value = this->fF51C;
        LeaveCriticalSection(&this->critSec);

        if (v32_value == 2) {
            if (this->fun_521BA0()) {
                GameActionCtx v60_gameAct;
                for_each_construct<GameAction, true>(v60_gameAct.actionArr, 16);
                memset(&v60_gameAct, 0, 0x11);

                v64_try_level = 0;
                if (!this->sub_524850(&v60_gameAct)
                    || !this->obj522000.sub_522300(&v60_gameAct)) {
                    v64_try_level = -1;
                    for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                    return 0;
                }
                int v33_gameTick = v60_gameAct.gameTick - 1;
                int v34_actGameTick = this->obj522000.__calcActionGameTick(v60_gameAct.gameTick - 1, 0x20u);
                int v35_actGameTick = v34_actGameTick;
                int v36_ticksLeft;
                if (v34_actGameTick) {
                    v36_ticksLeft = v33_gameTick - v34_actGameTick;
                } else {
                    v36_ticksLeft = 0;
                }
                this->ticksLeftBeforeAction = v36_ticksLeft;
                BOOL v41_sendResult;
                if (v36_ticksLeft) {
                    uint8_t message[sizeof(DataMessage_1) * 2];
                    uint8_t *pos = message;

                    DataMessage_1 *v61_messageBuf = (DataMessage_1 *) pos;
                    v61_messageBuf->init(&v60_gameAct);
                    int firstDataSize = v61_messageBuf->calcSize();
                    pos += firstDataSize;

                    DataMessage_1 *v38_secondDatamessage = (DataMessage_1 *) pos;
                    v38_secondDatamessage->gameTick0 = v35_actGameTick;
                    v38_secondDatamessage->gameTick5 = v33_gameTick;
                    v38_secondDatamessage->actionArr_count = -1;
                    int secondDataSize = v38_secondDatamessage->calcSize();

                    v41_sendResult = this->sendDataMessage(
                            1, message, secondDataSize + firstDataSize, 0xFFFFu
                    ) != 0;
                } else {
                    DataMessage_1 v61_messageBuf;
                    for_each_construct<GameAction, true>(v61_messageBuf.actionArr, 16);

                    v64_try_level = 1;
                    v61_messageBuf.init(&v60_gameAct);
                    int dataSize = v61_messageBuf.calcSize();
                    int v43_sendResult2 = this->sendDataMessage(1, &v61_messageBuf, dataSize, 0xFFFFu);
                    v64_try_level = 0;

                    if (v43_sendResult2) {
                        for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
                        v41_sendResult = 1;
                    } else {
                        for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
                        v41_sendResult = 0;
                    }
                }
                v64_try_level = -1;
                if (!v41_sendResult) {
                    for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                    return 0;
                }
                for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
            }
        }
    }

    int ff730_hiTck = 0;
    unsigned int f7260_gameTick = 0;
    if (this->gameActionCtxQueue.totalSize) {
        this->case2_timeMs = getTimeMs();
        struct MySemaphore v53_mySema;
        v53_mySema.set((uint32_t *) &this->MySemaphore, 0);
        v64_try_level = 2;
        if (!v53_mySema.waitFor(true)) {
            v64_try_level = -1;
            v53_mySema.release();
            return 0;
        }
        while (this->gameActionCtxQueue.totalSize) {
            if (this->gameActionCtxQueue.isLastCtxFull()) {
                DataMessage_1 v61_messageBuf;
                for_each_construct<GameAction, true>(v61_messageBuf.actionArr, 16);
                v64_try_level = 3;
                if (!this->gameActionCtxQueue.popMsg(&v61_messageBuf)) {
                    v53_mySema.release();
                    v64_try_level = 2;
                    for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
                    v64_try_level = -1;
                    v53_mySema.release();
                    return 0;
                }
                int f5_gameTick = v61_messageBuf.gameTick5;
                if (v61_messageBuf.gameTick5 > this->ff730_hiTck)
                    this->ff730_hiTck = v61_messageBuf.gameTick5;
                this->gameActionCtxArr.addCtx2(v61_messageBuf.gameTick0, f5_gameTick);
                v64_try_level = 2;
                for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
            } else {
                GameActionCtx v60_gameAct;
                for_each_construct<GameAction, true>(v60_gameAct.actionArr, 16);
                memset(&v60_gameAct, 0, 17);
                v64_try_level = 4;
                if (!this->gameActionCtxQueue.popToCtx(&v60_gameAct)) {
                    v53_mySema.release();
                    v64_try_level = 2;
                    for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                    v64_try_level = -1;
                    v53_mySema.release();
                    return 0;
                }
                if (v60_gameAct.gameTick > this->ff730_hiTck)
                    this->ff730_hiTck = v60_gameAct.gameTick;
                this->gameActionCtxArr.addCtx(&v60_gameAct);
                v64_try_level = 2;
                for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
            }
        }
        v53_mySema.release();
        v64_try_level = -1;
        v53_mySema.release();
    } else if (MyResources_instance.networkCfg._eos) {
        DWORD v53_timeMs = getTimeMs();
        if (v53_timeMs - this->case2_timeMs > 1000) {
            this->case2_timeMs = v53_timeMs;
            f7260_gameTick = this->gameActionCtxArr.gameTick;
            v60_doSendMessage = 1;
            ff730_hiTck = f7260_gameTick;
        }
    }
    int v49_foundResult = this->gameActionCtxArr._peekOrPop(a2_outCtx);
    if (v49_foundResult == 1) {
        this->updateTime_to__();
        if (!a2_outCtx->fE)
            ++this->ff734_unsafe;
        this->gameTickF72C = a2_outCtx->gameTick;
        return WeaNetR_instance.updatePlayers_isHost() || this->obj522000.sub_522300(a2_outCtx);
    }
    int v51_doSendMessage;
    if (v49_foundResult == 2) {
        ff730_hiTck = this->gameActionCtxArr.gameTick;
        v51_doSendMessage = 1;
        f7260_gameTick = ff730_hiTck;
    } else if (v49_foundResult ||
               (f7260_gameTick = this->gameActionCtxArr.gameTick, f7260_gameTick >= this->ff730_hiTck)) {
        v51_doSendMessage = v60_doSendMessage;
    } else {
        v51_doSendMessage = 1;
        ff730_hiTck = this->ff730_hiTck;
    }
    if (!v51_doSendMessage)
        return 0;
    int v52_sendTick = ff730_hiTck;
    if (!ff730_hiTck)
        v52_sendTick = f7260_gameTick;
#pragma pack(push, 1)
    struct DataPacket_3 {
        uint8_t packetTy;
        int gameTick;
        int sendTick;
    };
#pragma pack(pop)
    static_assert(sizeof(DataPacket_3) == 9u);
    DataPacket_3 packet;
    packet.packetTy = 3;
    packet.gameTick = f7260_gameTick;
    packet.sendTick = v52_sendTick;
    if (!WeaNetR_instance.sendDataMessage(&packet, sizeof(DataPacket_3), 0xFFFEu)) return 0;
    this->timeMsFDC8 = getTimeMs();
    ++this->ff728_req;
    return 0;
}
