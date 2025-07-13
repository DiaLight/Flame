//
// Created by DiaLight on 18.01.2025.
//

#include "dk2/CNetworkCommunication.h"

#include <patches/logging.h>

#include "dk2/CDefaultPlayerInterface.h"
#include "dk2/CWorld.h"
#include "dk2/MySemaphore.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/network/protocol.h"
#include "dk2/network/protocol/DataMessage_1.h"
#include "dk2/network/protocol/DataMessage_3.h"
#include "dk2/text/TbUniStringVTag.h"
#include "dk2/text/textmap/MyMbStringList.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2_memory.h"
#include "weanetr_dll/MLDPlay.h"


namespace dk2 {
    void collectActions_part1(CNetworkCommunication *self) {
        struct _RTL_CRITICAL_SECTION *p_fF504_critSec = &self->critSec;
        EnterCriticalSection(&self->critSec);
        LeaveCriticalSection(p_fF504_critSec);
        if (self->fF51C == 1)
            self->v_fun_521B40(1);
        if (!MyResources_instance.networkCfg._eos) {
            DWORD TimeMs = getTimeMs();
            if (WeaNetR_instance.updatePlayers_isHost()) {
                EnterCriticalSection(&self->critSec);
                int v5_timeMs = getTimeMs();
                unsigned int v6_slot = 0;
                ClientWorldState *clientWorldState = &self->clientWorldState[0];
                do {
                    if (WeaNetR_instance.isPlayerJoined(v6_slot)) {
                        if (!clientWorldState->lastPacket_timeMs)
                            clientWorldState->lastPacket_timeMs = v5_timeMs;
                        int v8_timeDelta = v5_timeMs - clientWorldState->lastPacket_timeMs;
                        if (v8_timeDelta < 0)
                            v8_timeDelta = 0;
                        if ((unsigned int) v8_timeDelta > 35000) {
                            MyPlayerInf v53_inf;
                            v53_inf.timeMs = v5_timeMs;
                            v53_inf.state = 3;
                            v53_inf.slot = v6_slot;
                            v53_inf.timeDelta = v8_timeDelta;
                            if (!self->containsPlayerInf(&v53_inf)) {
                                int fF720_playersCount = self->playersCount;
                                if (fF720_playersCount != 32) {
                                    int plIdx = ((BYTE) fF720_playersCount + (uint8_t) self->playersStart) & 0x1F;
                                    self->players[plIdx] = v53_inf;
                                    ++self->playersCount;
                                }
                            }
                        }
                    }
                    ++v6_slot;
                    ++clientWorldState;
                } while (v6_slot < 8);
                LeaveCriticalSection(&self->critSec);
            } else {
                if (self->gameActionCtxQueue.totalSize)
                    self->case2_timeMs = TimeMs;
                EnterCriticalSection(p_fF504_critSec);
                int v10_timeMs = getTimeMs();
                int v11_timeDelta = v10_timeMs - self->case2_timeMs;
                if (v11_timeDelta < 0)
                    v11_timeDelta = 0;
                LeaveCriticalSection(p_fF504_critSec);
                if ((unsigned int) v11_timeDelta > 35000) {
                    MyPlayerInf v53_inf;
                    v53_inf.timeMs = v10_timeMs;
                    v53_inf.state = 6;
                    v53_inf.timeDelta = v11_timeDelta;
                    if (!self->containsPlayerInf(&v53_inf)) {
                        int v12_playersCount = self->playersCount;
                        if (v12_playersCount != 32) {
                            self->players[((BYTE) v12_playersCount + (BYTE) self->playersStart) & 0x1F] = v53_inf;
                            ++self->playersCount;
                        }
                    }
                }
                if ((unsigned int) (v10_timeMs - self->lastSendWorldPacketTimeMs) > 1000)
                    self->v_f2C_sendData_20();
            }
        }
    }
    bool collectActions_part2(CNetworkCommunication *self) {
        while (2) {
            int v13_playersCount = self->playersCount;
            if (!v13_playersCount) break;
            int fF724_playersStart = self->playersStart;
            MyPlayerInf *v15_inf = &self->players[fF724_playersStart];
            int f0_state = v15_inf->state;
            DWORD f4_timeMs = v15_inf->timeMs;
            unsigned int v19_slot = v15_inf->slot;
            int v59_timeDelta = v15_inf->timeDelta;
            self->playersStart = ((BYTE) fF724_playersStart + 1) & 0x1F;
            self->playersCount = v13_playersCount - 1;
            switch (f0_state) {
                case 0:
                case 4: {
                    CWorld *f14_cworld = self->f0_profiler->cworld;
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
                    CWorld *v27_world = self->f0_profiler->cworld;
                    CWorld_instance.fA3C3 = f0_state != 1 ? 2113 : 2077;
                    v27_world->v_sub_509860(1);
                    return false;
                }
                case 2: {
                    int v24_timeMs = getTimeMs();
                    EnterCriticalSection(&self->critSec);
                    ClientWorldState *worldState = &self->clientWorldState[0];
                    int v26_left = 8;
                    do {
                        worldState->lastPacket_timeMs = v24_timeMs;
                        worldState++;
                        --v26_left;
                    } while (v26_left);
                    LeaveCriticalSection(&self->critSec);
                    self->case2_timeMs = v24_timeMs;
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
        return true;
    }
    bool collectActions_part3(CNetworkCommunication *self) {
        int v28_timeMs = getTimeMs();
        if (self->fF51C == 3) {
            int v29_doProcess = 1;
            EnterCriticalSection(&self->critSec);
            for (unsigned int i = 0; i < 8; ++i) {
                if (WeaNetR_instance.isPlayerJoined(i) && ((1 << i) & self->_playerMask) == 0)
                    v29_doProcess = 0;
            }
            LeaveCriticalSection(&self->critSec);
            if ((unsigned int) (v28_timeMs - self->_timefdd4) <= 15000) {
                if ((unsigned int) (v28_timeMs - self->timeoutThresholdTimeMs) > 1000) {
                    int value = self->lastScheduleOrderedInputTick;
                    self->sendDataMessage(0x29, &value, 4u, 0xFFFFu);
                    self->timeoutThresholdTimeMs = v28_timeMs;
                }
            } else {
                v29_doProcess = 1;
            }
            if (v29_doProcess) {
                CWorld *v31_world = self->f0_profiler->cworld;
                int v52_aBool = self->fFDF2;
                self->case2_timeMs = v28_timeMs;
                self->timeoutThresholdTimeMs = v28_timeMs;
                self->_timefdd4 = v28_timeMs;
                v31_world->v_fun_510E90(&self->gameAct, v52_aBool);
            }
        }
        EnterCriticalSection(&self->critSec);
        int v32_value = self->fF51C;
        LeaveCriticalSection(&self->critSec);

        if (v32_value == 2) {
            if (self->fun_521BA0()) {
                GameActionCtx v60_gameAct;
                for_each_construct<GameAction, true>(v60_gameAct.actionArr, 16);
                memset(&v60_gameAct, 0, 0x11);

                int v64_try_level = 0;
                if (!self->sub_524850(&v60_gameAct)
                    || !self->obj522000.sub_522300(&v60_gameAct)) {
                    v64_try_level = -1;
                    for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                    return false;
                }
                int v33_gameTick = v60_gameAct.gameTick - 1;
                int v34_actGameTick = self->obj522000.__calcActionGameTick(v60_gameAct.gameTick - 1, 0x20u);
                int v35_actGameTick = v34_actGameTick;
                int v36_ticksLeft;
                if (v34_actGameTick) {
                    v36_ticksLeft = v33_gameTick - v34_actGameTick;
                } else {
                    v36_ticksLeft = 0;
                }
                self->ticksLeftBeforeAction = v36_ticksLeft;
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

                    v41_sendResult = self->sendDataMessage(
                            DK2Packet_1_ActionArr::ID, message, secondDataSize + firstDataSize, 0xFFFFu
                    ) != 0;
                } else {
                    DataMessage_1 v61_messageBuf;
                    for_each_construct<GameAction, true>(v61_messageBuf.actionArr, 16);

                    v64_try_level = 1;
                    v61_messageBuf.init(&v60_gameAct);
                    int dataSize = v61_messageBuf.calcSize();
                    int v43_sendResult2 = self->sendDataMessage(DK2Packet_1_ActionArr::ID, &v61_messageBuf, dataSize, 0xFFFFu);
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
                for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                if (!v41_sendResult) {
                    return false;
                }
            }
        }
        return true;
    }
    bool collectActions_part4(CNetworkCommunication *self, MySemaphore &v53_mySema) {
        int v64_try_level = 2;
        if (!v53_mySema.waitFor(true)) {
            v64_try_level = -1;
            return false;
        }
        while (self->gameActionCtxQueue.totalSize) {
            if (self->gameActionCtxQueue.isLastCtxFull()) {
                DataMessage_1 v61_messageBuf;
                for_each_construct<GameAction, true>(v61_messageBuf.actionArr, 16);
                v64_try_level = 3;
                if (!self->gameActionCtxQueue.popMsg(&v61_messageBuf)) {
                    v64_try_level = 2;
                    for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
                    v64_try_level = -1;
                    return false;
                }
                int f5_gameTick = v61_messageBuf.gameTick5;
                if (v61_messageBuf.gameTick5 > self->ff730_highTick)
                    self->ff730_highTick = v61_messageBuf.gameTick5;
                self->gameActionCtxArr.addCtx2(v61_messageBuf.gameTick0, f5_gameTick);
                v64_try_level = 2;
                for_each_destruct<GameAction, true>(v61_messageBuf.actionArr, 16);
            } else {
                GameActionCtx v60_gameAct;
                for_each_construct<GameAction, true>(v60_gameAct.actionArr, 16);
                memset(&v60_gameAct, 0, 17);
                v64_try_level = 4;
                if (!self->gameActionCtxQueue.popToCtx(&v60_gameAct)) {
                    v64_try_level = 2;
                    for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
                    v64_try_level = -1;
                    return false;
                }
                if (v60_gameAct.gameTick > self->ff730_highTick)
                    self->ff730_highTick = v60_gameAct.gameTick;
                self->gameActionCtxArr.addCtx(&v60_gameAct);
                v64_try_level = 2;
                for_each_destruct<GameAction, true>(v60_gameAct.actionArr, 16);
            }
        }
        v64_try_level = -1;
        return true;
    }
}
int dk2::GameActionCtxArr::tryPopCtx(GameActionCtx *a2_outCtx) {
    if (this->actionCtx_arr[this->startGameTick % 0x60].gameTick != this->startGameTick)
        return this->orderedInputCount != 0 ? 2 : 0;
    *a2_outCtx = this->actionCtx_arr[this->startGameTick % 0x60];
    int v4_gameTick = this->startGameTick + 1;
    --this->orderedInputCount;
    this->startGameTick = v4_gameTick;
    return 1;
}

BOOL dk2::CNetworkCommunication::collectActions(GameActionCtx *a2_outCtx) {
    collectActions_part1(this);
    if(!collectActions_part2(this)) return 0;

    if (WeaNetR_instance.updatePlayers_isHost()) {
        if(!collectActions_part3(this)) return 0;
    }


    int v60_doSendMessage = 0;
    int ff730_endTick = 0;
    unsigned int f7260_startTick = 0;
    if (this->gameActionCtxQueue.totalSize) {
        this->case2_timeMs = getTimeMs();
        MySemaphore v53_mySema;
        v53_mySema.set(&this->hMySemaphore, 0);
        if(!collectActions_part4(this, v53_mySema)) {
            v53_mySema.release();
            return 0;
        }
        v53_mySema.release();
    } else if (MyResources_instance.networkCfg._eos) {
        DWORD nowTimeMs = getTimeMs();
        if (nowTimeMs - this->case2_timeMs > 1000) {
            this->case2_timeMs = nowTimeMs;
            f7260_startTick = ff730_endTick = this->gameActionCtxArr.startGameTick;
            v60_doSendMessage = 1;
        }
    }
    int v49_foundResult = this->gameActionCtxArr.tryPopCtx(a2_outCtx);
    if (v49_foundResult == 1) {  // found ctx
        this->updateTime_to__();
        if (!a2_outCtx->fE)
            ++this->ff734_unsafe;
        this->lastScheduleOrderedInputTick = a2_outCtx->gameTick;
        return WeaNetR_instance.updatePlayers_isHost() || this->obj522000.sub_522300(a2_outCtx);
    }
    int v51_doSendMessage;
    if (v49_foundResult == 2) {  // has ordered inputs
        f7260_startTick = ff730_endTick = this->gameActionCtxArr.startGameTick;
        v51_doSendMessage = 1;
    } else if (v49_foundResult) {  // found ctx or has ordered inputs
        v51_doSendMessage = v60_doSendMessage;
    } else {
        f7260_startTick = this->gameActionCtxArr.startGameTick;
        if (f7260_startTick >= this->ff730_highTick) {
            v51_doSendMessage = v60_doSendMessage;
        } else {
            v51_doSendMessage = 1;
            ff730_endTick = this->ff730_highTick;
        }
    }
    // patch::log::dbg("skip sending %d-%d", f7260_startTick, ff730_endTick);
    if (!v51_doSendMessage) return 0;
    DK2Packet_3_ResendActionsRequest packet;
    packet.packetId = DK2Packet_3_ResendActionsRequest::ID;
    packet.times.startTick = f7260_startTick;
    packet.times.endTick = ff730_endTick ? ff730_endTick : f7260_startTick;
    if (!WeaNetR_instance.sendDataMessage(&packet, sizeof(DK2Packet_3_ResendActionsRequest), 0xFFFEu)) return 0;

    this->lastSendWorldPacketTimeMs = getTimeMs();
    ++this->ff728_req;
    return 0;
}

int dk2::CNetworkCommunication::resendMissingActions(DataMessage_3 *a2_msg, unsigned int a3_slot) {
    GameActionCtx v23_actionCtx;
    for_each_construct<GameAction, true>(v23_actionCtx.actionArr, 16);
    memset(&v23_actionCtx, 0, 0x11);
    unsigned int f8__gameTick8 = this->obj522000._gameTick8;
    int try_level = 0;
    if (a2_msg->startTick > f8__gameTick8) {
        try_level = -1;
        for_each_destruct<GameAction, true>(v23_actionCtx.actionArr, 16);
        return 0;
    }
    for (
        unsigned int v20_i = 0, v19_curTick = a2_msg->startTick;
        v20_i < 0x20 && v19_curTick <= a2_msg->endTick;
        ++v20_i, ++this->resendsCnt, ++v19_curTick
    ) {
        if (!this->obj522000.sub_5224E0(v19_curTick, &v23_actionCtx)) {
            MyPlayerInf v22_inf;
            v22_inf.timeMs = getTimeMs();
            v22_inf.state = 5;
            v22_inf.slot = a3_slot;
            v22_inf.timeDelta = v19_curTick;
            if (!this->containsPlayerInf(&v22_inf)) {
                int fF720_playersCount = this->playersCount;
                if (fF720_playersCount != 32) {
                    this->players[((BYTE) fF720_playersCount + (BYTE) this->playersStart) & 0x1F] = v22_inf;
                    ++this->playersCount;
                }
            }
            WeaNetR_instance.mldplay->DumpPlayer(a3_slot);  // DestroySession
            try_level = -1;
            for_each_destruct<GameAction, true>(v23_actionCtx.actionArr, 16);
            return 0;
        }
        unsigned int v6_nextTick = v19_curTick + 1;
        int v7_gameTick = this->obj522000.sub_5222C0(v6_nextTick, 0x20u);
        int v8_ticks = v7_gameTick;
        unsigned int v9_ticksLeft;
        if (v7_gameTick)
            v9_ticksLeft = v7_gameTick - v6_nextTick;
        else
            v9_ticksLeft = 0;
        BOOL v14_sendStatus = FALSE;
        if (v9_ticksLeft) {
            DataMessage_1 v25_dataMsg;
            v25_dataMsg.init(&v23_actionCtx);
            int f4_actionArr_count;
            if (v25_dataMsg.actionArr_count == 0xFF)
                f4_actionArr_count = 0;
            else
                f4_actionArr_count = v25_dataMsg.actionArr_count;
            DataMessage_1 *v11_secondMsg = (DataMessage_1 *) &v25_dataMsg.actionArr[f4_actionArr_count];
            v11_secondMsg->gameTick0 = v6_nextTick;
            v11_secondMsg->actionArr_count = -1;
            v11_secondMsg->sub_524CA0(v8_ticks);
            int v12_firstSize = v25_dataMsg.calcSize();
            int v13_secondSize = v11_secondMsg->calcSize();
            if(this->sendDataMessage(
                    DK2Packet_1_ActionArr::ID,
                    &v25_dataMsg,
                    v13_secondSize + v12_firstSize,
                    a3_slot) != 0) {
                v14_sendStatus = TRUE;
            }
            v19_curTick += v9_ticksLeft;
        } else {
            DataMessage_1 v24_dataMsg;
            for_each_construct<GameAction, true>(v24_dataMsg.actionArr, 16);
            try_level = 1;
            v24_dataMsg.init(&v23_actionCtx);
            int v15_msgSize = v24_dataMsg.calcSize();
            int v16_sendStatus = this->sendDataMessage(DK2Packet_1_ActionArr::ID, &v24_dataMsg, v15_msgSize, a3_slot);
            try_level = 0;
            for_each_destruct<GameAction, true>(v24_dataMsg.actionArr, 16);
            if (v16_sendStatus) {
                v14_sendStatus = TRUE;
            }
        }
        if (!v14_sendStatus) {
            try_level = -1;
            for_each_destruct<GameAction, true>(v23_actionCtx.actionArr, 16);
            return 0;
        }
    }
    try_level = -1;
    for_each_destruct<GameAction, true>(v23_actionCtx.actionArr, 16);
    return 1;
}


void __cdecl dk2::CNetworkCommunication_dataCallback(
        void *a1_message,
        int a2_messageSize,
        unsigned int a3_playersSlot,
        CNetworkCommunication *a4_arg) {

    a4_arg->clientWorldState[a3_playersSlot].lastPacket_timeMs = getTimeMs();
    auto *hdr = (DK2PacketHeader *) a1_message;
    switch ( hdr->packetId ) {
        case DK2Packet_1_ActionArr::ID: {
            auto *pkt = (DK2Packet_1_ActionArr *) a1_message;
            DataMessage_1 *v10_pos = &pkt->data;
            int v11_sizeLeft = a2_messageSize - 1;
            if (a2_messageSize != 1) {
                do {
                    if (!a4_arg->pushDataMsg(v10_pos))
                        break;
                    int v12 = v10_pos->actionArr_count == 0xFF ? 0 : v10_pos->actionArr_count;
                    int v13_itemSize = sizeof(GameAction) * v12 + 0xF;
                    v11_sizeLeft -= v13_itemSize;
                    v10_pos = (DataMessage_1 *) ((char *) v10_pos + v13_itemSize);
                } while (v11_sizeLeft);
            }
            EnterCriticalSection(&a4_arg->critSec);
            if (a4_arg->fF51C == 1)
                a4_arg->fF51C = 2;
            LeaveCriticalSection(&a4_arg->critSec);
            return;
        }
        case DK2Packet_2_GameAction::ID: {
            auto *pkt = (DK2Packet_2_GameAction *) a1_message;
            a4_arg->addAction(&pkt->act);
            return;
        }
        case DK2Packet_3_ResendActionsRequest::ID: {
            auto *pkt = (DK2Packet_3_ResendActionsRequest *) a1_message;
            a4_arg->resendMissingActions(&pkt->times, a3_playersSlot);
            EnterCriticalSection(&a4_arg->critSec);
            if (a4_arg->fF51C == 1)
                a4_arg->fF51C = 2;
            LeaveCriticalSection(&a4_arg->critSec);
            return;
        }
        case DK2Packet_B_UploadTrackPing::ID: {
            auto *pkt = (DK2Packet_B_UploadTrackPing *) a1_message;
            if (WeaNetR_instance.updatePlayers_isHost())
                return;
            // server->client  [BC] in B{1,00000003}  pl=0 cpl=1
            patch::log::dbg("[UploadTrackPing] in B{%d,%08X}  pl=%d cpl=%d", (uint16_t) pkt->f0_save2else1, pkt->f4_slotMask, a3_playersSlot, WeaNetR_instance.playersSlot);
            char f1D4_playersSlot = WeaNetR_instance.playersSlot;
            uint16_t v15_save2else1 = (uint16_t) pkt->f0_save2else1;
            int v16_slotMask = pkt->f4_slotMask;
            a4_arg->slotMasks[v15_save2else1] = v16_slotMask;
            if (a4_arg->fFDB4[v15_save2else1] != 1)
                return;
            if (((1 << f1D4_playersSlot) & v16_slotMask) == 0) {
                EnterCriticalSection(&a4_arg->critSec);
                a4_arg->v_f24_sendData_C_UploadTrackPong(v15_save2else1, 4343);
                LeaveCriticalSection(&a4_arg->critSec);
            }
            EnterCriticalSection(&a4_arg->critSec);
            unsigned int slot = 0;
            do {
                a4_arg->clientWorldState[slot].f0[v15_save2else1] = (v16_slotMask & (1 << slot)) != 0;
                slot++;
            } while (slot < 8);
            LeaveCriticalSection(&a4_arg->critSec);
            return;
        }
        case DK2Packet_C_UploadTrackPong::ID: {
            auto *pkt = (DK2Packet_C_UploadTrackPong *) a1_message;
            if (!WeaNetR_instance.updatePlayers_isHost())
                return;
            EnterCriticalSection(&a4_arg->critSec);
            // client->server  [BC] in C{1,4343}  pl=1
            patch::log::dbg("[UploadTrackPong] in {%d,%d}  pl=%d", pkt->f0_save2else1, pkt->f4_4343, a3_playersSlot);
            unsigned int v19_slot = pkt->f0_save2else1;
            a4_arg->clientWorldState[a3_playersSlot].checksum = pkt->f4_4343;
            if (v19_slot < 4) {
                a4_arg->clientWorldState[a3_playersSlot].f0[v19_slot] = 1;
                a4_arg->slotMasks[v19_slot] |= 1 << a3_playersSlot;
            }
            LeaveCriticalSection(&a4_arg->critSec);
            return;
        }
        case DK2Packet_15_WorldChecksum::ID: {
            auto *pkt = (DK2Packet_15_WorldChecksum *) a1_message;
            if (!WeaNetR_instance.updatePlayers_isHost())
                return;
            EnterCriticalSection(&a4_arg->critSec);
            unsigned int v8_gameTick = pkt->f0_gameTick;
            if (v8_gameTick > a4_arg->fFDC4)
                a4_arg->fFDC4 = v8_gameTick;
            if (v8_gameTick <= a4_arg->clientWorldState[a3_playersSlot].gameTick) {
                LeaveCriticalSection(&a4_arg->critSec);
                break;
            }
            a4_arg->clientWorldState[a3_playersSlot].gameTick = v8_gameTick;
            a4_arg->clientWorldState[a3_playersSlot].checksum = pkt->f4_checksum;
            LeaveCriticalSection(&a4_arg->critSec);
            break;
        }
        case DK2Packet_1F_LoadLevelStatus::ID: {
            auto *pkt = (DK2Packet_1F_LoadLevelStatus *) a1_message;
            EnterCriticalSection(&a4_arg->critSec);
            if (pkt->f0_zero >= 4) {
                LeaveCriticalSection(&a4_arg->critSec);
                return;
            }
            a4_arg->clientWorldState[a3_playersSlot].loadLevelStatus[pkt->f0_zero] = pkt->f4_loadStatus;
            LeaveCriticalSection(&a4_arg->critSec);
        } return;
        case DK2Packet_29_Ping::ID: {
            auto *pkt = (DK2Packet_29_Ping *) a1_message;
            if (WeaNetR_instance.updatePlayers_isHost())
                return;
            int dword_f72c = a4_arg->lastScheduleOrderedInputTick;
            EnterCriticalSection(&a4_arg->critSec);
            a4_arg->fF51C = 3;
            LeaveCriticalSection(&a4_arg->critSec);

            DK2Packet_2A_Pong msg;
            msg.packetId = DK2Packet_2A_Pong::ID;
            msg.gameTick = dword_f72c;
            if (WeaNetR_instance.sendDataMessage(&msg, sizeof(msg), 0xFFFFu)) {
                int TimeMs = getTimeMs();
                a4_arg->lastSendWorldPacketTimeMs = TimeMs;
                a4_arg->timeMsFDCC = TimeMs;
            }
            if (dword_f72c != pkt->gameTick)
                return;
            EnterCriticalSection(&a4_arg->critSec);
            a4_arg->fF51C = 2;
            LeaveCriticalSection(&a4_arg->critSec);
            break;
        }
        case DK2Packet_2A_Pong::ID: {
            auto *pkt = (DK2Packet_2A_Pong *) a1_message;
            if (WeaNetR_instance.updatePlayers_isHost()
                && pkt->gameTick == a4_arg->lastScheduleOrderedInputTick) {
                a4_arg->_playerMask |= 1 << a3_playersSlot;
            }
            return;
        }
        default:
            return;
    }
}

int dk2::CNetworkCommunication::uploadMapInit(int a2_slot) {
    Obj523DE1 *v4 = &this->obj523DE1_arr[a2_slot];
    struct _RTL_CRITICAL_SECTION *p_fF504_critSec = &this->critSec;
    v4->timing1 = 200000;
    v4->timing2 = 160000;
    v4->timing3 = 1500;
    v4->timing4 = 206000;
    v4->timing5 = 30000;
    v4->_abool = 1;
    EnterCriticalSection(&this->critSec);
    for (int i = 0; i < 32; ++i) {
        this->clientWorldState[i].f0[a2_slot] = 0;
        this->clientWorldState[i].gameTick = 0;
        this->clientWorldState[i].checksum = 0;
    }
    this->fFDC4 = 0;
    this->slotMasks[a2_slot] = 0;
    LeaveCriticalSection(p_fF504_critSec);
    DWORD TimeMs = getTimeMs();
    v4->timeMs1 = TimeMs;
    v4->timeMs2 = TimeMs;
    if (!WeaNetR_instance.getCurrentPlayersCount(&v4->_playersCount))
        return -1;
    int f1D4_playersSlot = WeaNetR_instance.playersSlot;
    this->fFDB4[a2_slot] = 1;
    if (WeaNetR_instance.updatePlayers_isHost()) {
        EnterCriticalSection(p_fF504_critSec);
        this->clientWorldState[f1D4_playersSlot].f0[a2_slot] = 1;
        this->clientWorldState[f1D4_playersSlot].checksum = 4343;
        this->slotMasks[a2_slot] |= 1 << f1D4_playersSlot;
        LeaveCriticalSection(p_fF504_critSec);
        if (v4->_playersCount <= 1u)
            return -1;
    } else {
        this->v_f24_sendData_C_UploadTrackPong(a2_slot, 4343);
    }
    return 0;
}

uint32_t dk2::CNetworkCommunication::uploadMapFinish(int a2_save2else1) {
    this->obj523DE1_arr[a2_save2else1]._abool = 0;
    this->slotMasks[a2_save2else1] = 0;
    this->fFDB4[a2_save2else1] = 0;
    int TimeMs = getTimeMs();
    DWORD v10_notDestroyedCount = 0;
    for (int v3_slot = 0; v3_slot < 8; ++v3_slot) {
        ClientWorldState *worldState = &this->clientWorldState[v3_slot];
        if (!WeaNetR_instance.isPlayerJoined(v3_slot)) continue;
        if (!worldState->f0[a2_save2else1]) {
            WeaNetR_instance.mldplay->DumpPlayer(v3_slot);  // DestroySession
            continue;
        }
        worldState->lastPacket_timeMs = TimeMs;
        ++v10_notDestroyedCount;
    }
    this->obj523DE1_arr[a2_save2else1]._notDestroyedPlayers = v10_notDestroyedCount;
    return v10_notDestroyedCount;
}
int dk2::CNetworkCommunication::fun_523EA0(int a2_save2else1) {
    int v2_save2else1 = a2_save2else1;
    if (this->v_fun_5239E0_uploadMapInit(a2_save2else1) < 0)
        return 0;
    int v4___time = 0;
    while (2) {
        if (this->funFE02) this->funFE02(this->ise);
        unsigned int plSlot;
        int v6_status = this->v_fun_523B30_uploadMapTrack(v2_save2else1, &plSlot, v4___time);
        if (v4___time) v4___time = 0;
        switch (v6_status) {
            case -5:
            case -4:
                this->v_fun_523DC0_uploadMapFinish(v2_save2else1);
                return 0;
            case -3:
                v4___time = 5000;
                continue;
            case -2: {
                int isHost = WeaNetR_instance.updatePlayers_isHost();
                if (!isHost) {
                    this->v_fun_523DC0_uploadMapFinish(v2_save2else1);
                    return 0;
                }
                if (this->v_fun_523DC0_uploadMapFinish(v2_save2else1) < 2) return 0;
                if (this->clientWorldState[WeaNetR_instance.playersSlot].f0[v2_save2else1] != 1) return 0;
                EnterCriticalSection(&this->critSec);
                this->fF51C = 2;
                LeaveCriticalSection(&this->critSec);
                return 1;
            }
            case 0:
                this->v_fun_523DC0_uploadMapFinish(v2_save2else1);
                EnterCriticalSection(&this->critSec);
                this->fF51C = 2;
                LeaveCriticalSection(&this->critSec);
                return 1;
            case 1:
                continue;
            default:
                this->v_fun_523DC0_uploadMapFinish(v2_save2else1);
                return 0;
        }
    }
}



