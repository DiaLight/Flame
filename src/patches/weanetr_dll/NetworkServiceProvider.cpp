//
// Created by DiaLight on 17.12.2024.
//

#include "NetworkServiceProvider.h"
#include "structs.h"
#include "messages.h"
#include "logging.h"
#include "weanetr_memory.h"
#include "patches/logging.h"

using namespace net;

int NetworkServiceProvider::Startup(MessageHandlerType handler) {
    InitializeCriticalSection(&this->dataLock);
    this->messageHandler = handler;
    return 1;
}

int NetworkServiceProvider::ShutDown() {
    _log("\tNetworkServiceProvider::ShutDown Called\n");
    DeleteCriticalSection(&this->dataLock);
    if ( !this->f24_playerList )
        return 1;
    net::_free(this->f24_playerList);
    this->f24_playerList = NULL;
    return 1;
}

int NetworkServiceProvider::destroySystemThread() {
    if (this->h166_OnStopDeliverThread_hEvent == NULL) return 0;
    SetEvent(this->h166_OnStopDeliverThread_hEvent);
    int isThreadAlive = 1;
    do {
        EnterCriticalSection(&this->dataLock);
        if ( this->f41B_SendDeliverThread_hThread == INVALID_HANDLE_VALUE )
            isThreadAlive = 0;
        LeaveCriticalSection(&this->dataLock);
    } while ( isThreadAlive );
    _log("DESTROYED SYSTEM THREAD\n");
    CloseHandle(this->h166_OnStopDeliverThread_hEvent);
    CloseHandle(this->f16A_playerCountChange_hEvent);
    this->h166_OnStopDeliverThread_hEvent = NULL;
    this->f16A_playerCountChange_hEvent = NULL;
    return 0;
}

int NetworkServiceProvider::destroyMainThread() {
    _log("DestroyingServiceProvider Thread\n");
    if ( this->f176_OnTerminateNspThread_hEvent )
        SetEvent(this->f176_OnTerminateNspThread_hEvent);
    if ( this->f17e_NetworkServiceProvider_hThread != INVALID_HANDLE_VALUE ) {
        int isThreadAlive = 1;
        do {
            EnterCriticalSection(&this->dataLock);
            if ( this->f17e_NetworkServiceProvider_hThread == (HANDLE)-1 )
                isThreadAlive = 0;
            LeaveCriticalSection(&this->dataLock);
            Sleep(5u);
        } while ( isThreadAlive );
    }
    _log("DESTROYED MAIN THREAD\n");
    if ( this->f172_OnPlayerJoined_hEvent ) {
        CloseHandle(this->f172_OnPlayerJoined_hEvent);
        this->f172_OnPlayerJoined_hEvent = NULL;
    }
    if ( this->f176_OnTerminateNspThread_hEvent ) {
        CloseHandle(this->f176_OnTerminateNspThread_hEvent);
        this->f176_OnTerminateNspThread_hEvent = NULL;
    }
    if ( this->f17a_OnPacket_D_Guaranteed_added_hEvent ) {
        CloseHandle(this->f17a_OnPacket_D_Guaranteed_added_hEvent);
        this->f17a_OnPacket_D_Guaranteed_added_hEvent = NULL;
    }
    this->f182_unused2 = 0;
    return 1;
}

int NetworkServiceProvider::Destroy() {
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tNetworkServiceProvider::DestroySession Error::ServiceProvider Not Initialised\n");
        return 0;
    }
    if (!this->f226_curPlayer.isConnectedToSession())
        return 0;
    int result = this->DestroySPSession();
    this->destroySystemThread();
    this->destroyMainThread();
    if ( this->f24_playerList ) {
        net::_free(this->f24_playerList);
        this->f24_playerList = NULL;
    }
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    this->f45F_getHostByName_isPresent = 0;
    this->f563_getHostByName_port = 7575;
    memset(this->f463_getHostByName_host, 0, sizeof(this->f463_getHostByName_host));
    return result;
}

int NetworkServiceProvider::CreateServiceProvider() {
    if ( this->f17e_NetworkServiceProvider_hThread != INVALID_HANDLE_VALUE )
        return TRUE;
    HANDLE hEvent = CreateEventA(NULL, 0, 0, NULL);
    this->f17a_OnPacket_D_Guaranteed_added_hEvent = hEvent;
    if (!hEvent) {
        _log("NetworkServiceProvider::CreateServiceProvider Error:-Cannot Create Guaranteed Thread Event\n");
        return FALSE;
    }
    HANDLE v3_hEvent = CreateEventA(NULL, 0, 0, NULL);
    this->f172_OnPlayerJoined_hEvent = v3_hEvent;
    if (!v3_hEvent) {
        _log("NetworkServiceProvider::CreateServiceProvider Error:-Cannot Create StartThread Event\n");
        CloseHandle(this->f17a_OnPacket_D_Guaranteed_added_hEvent);
        this->f17a_OnPacket_D_Guaranteed_added_hEvent = NULL;
        return FALSE;
    }
    HANDLE v4_hEvent = CreateEventA(NULL, 0, 0, NULL);
    this->f176_OnTerminateNspThread_hEvent = v4_hEvent;
    if (!v4_hEvent) {
        CloseHandle(this->f172_OnPlayerJoined_hEvent);
        HANDLE f17a_handle3_event = this->f17a_OnPacket_D_Guaranteed_added_hEvent;
        this->f172_OnPlayerJoined_hEvent = 0;
        CloseHandle(f17a_handle3_event);
        this->f17a_OnPacket_D_Guaranteed_added_hEvent = NULL;
        _log("NetworkServiceProvider::CreateServiceProvider Error:-Cannot Create killThread Event\n");
        return FALSE;
    }
    HANDLE v5_hThread = (HANDLE) _beginthread([](void *arg) {
        auto *self = (NetworkServiceProvider *) arg;
        _log("IDLE NetworkServiceProvider Thread\n");
        HANDLE f176_handle2 = self->f176_OnTerminateNspThread_hEvent;
        HANDLE Handles[2];
        Handles[0] = self->f172_OnPlayerJoined_hEvent;
        Handles[1] = f176_handle2;
        DWORD waitResult = WaitForMultipleObjects(2u, Handles, 0, INFINITE);
        if (waitResult) {
            if (waitResult == 1)
                _log("TERMINATING NetworkServiceProvider Thread\n");
        } else {
            _log("STARTING NetworkServiceProvider Thread\n");
            self->processSPMessages();
        }
        _log("LEAVING NetworkServiceProvider THREAD\n");
        EnterCriticalSection(&self->dataLock);
        self->f17e_NetworkServiceProvider_hThread = (HANDLE) -1;
        LeaveCriticalSection(&self->dataLock);
    }, 0, this);
    this->f17e_NetworkServiceProvider_hThread = v5_hThread;
    if (v5_hThread == INVALID_HANDLE_VALUE) {
        _log("NetworkServiceProvider::CreateServiceProvider Error:-Cannot Create Thread \n");
        CloseHandle(this->f172_OnPlayerJoined_hEvent);
        CloseHandle(this->f176_OnTerminateNspThread_hEvent);
        CloseHandle(this->f17a_OnPacket_D_Guaranteed_added_hEvent);
        this->f17a_OnPacket_D_Guaranteed_added_hEvent = NULL;
        this->f172_OnPlayerJoined_hEvent = NULL;
        this->f176_OnTerminateNspThread_hEvent = NULL;
        return FALSE;
    }
    SetThreadPriority(v5_hThread, 2);
    return TRUE;
}

void NetworkServiceProvider::SendDeliverThread() {
    DWORD v1_sleepTime = -1;
    _log("\nNetworkServiceProvider::Starting SendDeliverThread Thread\n");
    struct mmtime_tag pmmt;
    timeGetSystemTime(&pmmt, 0xCu);
    DWORD sizeToProcessLimit = 100000;
    int v18_endLoop = 0;
    while ( !v18_endLoop ) {
        HANDLE handlesArr[4];
        handlesArr[0] = this->f16A_playerCountChange_hEvent;  // process
        handlesArr[1] = this->h166_OnStopDeliverThread_hEvent;  // stop
        handlesArr[2] = this->f17a_OnPacket_D_Guaranteed_added_hEvent;  // process
        DWORD v6_countHandles = 3;
        if ( this->f16E_OnUnused_hEvent ) {
            handlesArr[3] = this->f16E_OnUnused_hEvent;
            v6_countHandles = 4;
        }
        DWORD v7_status = WaitForMultipleObjects(v6_countHandles, handlesArr, 0, v1_sleepTime);
        if ( v7_status == 0 ) {  // onPlayerCountChange
            // pass
        } else if ( v7_status == 1 ) {  // onStopDeliverThread
            _log("\nNetworkServiceProvider::SendDeliverThread got a message to kill event\n");
            v18_endLoop = 1;
            continue;
        } else if ( v7_status == 2 ) {  // onGuaranteed_D_Packet
            // pass
        } else if ( v7_status == 3 ) {
            continue;
        } else if (v7_status == STATUS_TIMEOUT) {
            // pass
        } else {
            _log("\tWaitForEvents Error Occurred in SendDeliverThread\n");
            continue;
        }

        v1_sleepTime = -1;
        unsigned int selfa_sleepTime = -1;
        EnterCriticalSection(&this->dataLock);
        struct mmtime_tag v19_sysTime;
        timeGetSystemTime(&v19_sysTime, 0xCu);
        this->queuePacketToSend(NULL);
        DWORD sysTime_ms = v19_sysTime.u.ms;
        unsigned int v9_systemSlot = 0;
        for (int i = 0; i < 50; ++i) {
            ScheduledPacket *v11_curPacket = this->f26F_packetSendToAllArr[i];
            if (!v11_curPacket) continue;
            if ( sysTime_ms - v11_curPacket->f1C_addedTime >= v11_curPacket->f10__60000 ) {
                _log("CLIENT HAS NOT RESPONDED TO SYSTEM MESSAGE REMOVING SYSTEM SLOT %d.\n", v9_systemSlot);
                net::_free(v11_curPacket);
                this->f26F_packetSendToAllArr[i] = NULL;
                sysTime_ms = v19_sysTime.u.ms;
                continue;
            }
            int f18_lastSendTime = v11_curPacket->f18_lastSendTime;
            unsigned int f14_timeSendDelta = v11_curPacket->f14_timeSendDelta;
            if (sysTime_ms - f18_lastSendTime < f14_timeSendDelta) {
                DWORD v15_relTime = f18_lastSendTime + f14_timeSendDelta - sysTime_ms;
                v1_sleepTime = selfa_sleepTime;
                if (v15_relTime < selfa_sleepTime) {
                    v1_sleepTime = v15_relTime;
                    selfa_sleepTime = v15_relTime;
                }
                continue;
            }
            v11_curPacket->f18_lastSendTime = sysTime_ms;
            this->sendScheduledPacketToAllPlayers(v11_curPacket);
            v1_sleepTime = selfa_sleepTime;
            if (v11_curPacket->f14_timeSendDelta < selfa_sleepTime) {
                v1_sleepTime = v11_curPacket->f14_timeSendDelta;
                selfa_sleepTime = v1_sleepTime;
            }
            sysTime_ms = v19_sysTime.u.ms;
        }

        if ( sysTime_ms - pmmt.u.ms >= 1000 ) {
            timeGetSystemTime(&pmmt, 0xCu);
            sysTime_ms = v19_sysTime.u.ms;
            sizeToProcessLimit = 100000;
        }
        DWORD v12_sleepReq = this->processDeliverHeaders(
                &this->f25F_deliverHeadersQueue,
                sysTime_ms,
                &sizeToProcessLimit);
        if ( v12_sleepReq != -1 && v12_sleepReq < v1_sleepTime )
            v1_sleepTime = v12_sleepReq;
        LeaveCriticalSection(&this->dataLock);
    }
    this->releasePacketSendArr();
    this->releasePacketSendQueue();
    _log("\nNetworkServiceProvider::Ending SendDeliverThread Thread\n");
    EnterCriticalSection(&this->dataLock);
    this->f41B_SendDeliverThread_hThread = INVALID_HANDLE_VALUE;
    this->releaseDeliverQueues();
    LeaveCriticalSection(&this->dataLock);
}

int NetworkServiceProvider::startSendDeliverThread() {
    int result = 0;
    if ( this->f41B_SendDeliverThread_hThread != INVALID_HANDLE_VALUE )
        return 1;
    memset(this->f26F_packetSendToAllArr, 0, sizeof(this->f26F_packetSendToAllArr));
    HANDLE EventA = CreateEventA(NULL, 0, 0, NULL);
    this->h166_OnStopDeliverThread_hEvent = EventA;
    if ( !EventA )
        return result;
    HANDLE v4_hEvent = CreateEventA(NULL, 0, 0, NULL);
    this->f16A_playerCountChange_hEvent = v4_hEvent;
    if ( !v4_hEvent ) {
        CloseHandle(this->h166_OnStopDeliverThread_hEvent);
        this->h166_OnStopDeliverThread_hEvent = NULL;
        return 0;
    }
    HANDLE v5_hThread = (HANDLE) _beginthread([](void *arg) {
        auto *self = (NetworkServiceProvider *) arg;
        self->SendDeliverThread();
    }, 0, this);
    this->f41B_SendDeliverThread_hThread = v5_hThread;
    if ( v5_hThread != INVALID_HANDLE_VALUE )
        return 1;
    CloseHandle(this->h166_OnStopDeliverThread_hEvent);
    CloseHandle(this->f16A_playerCountChange_hEvent);
    this->h166_OnStopDeliverThread_hEvent = NULL;
    this->f16A_playerCountChange_hEvent = NULL;
    return 0;
}

int NetworkServiceProvider::CreateSession(
        DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
        MySessionCredentials *a5_cred, int a6_flags) {
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tNetworkServiceProvider::CreateSession Error::ServiceProvider Not Initialised\n");
        return 0x20;
    }
    if (this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::CreateSession Error::Already Connected To Session\n");
        return 0x20;
    }
    if ( !a5_cred ) {
        _log("\tNetworkServiceProvider::CreateSession Error::No Credentials supplied\n");
        return 0x200;
    }
    if ( a5_cred->f0_credentialParameterSize < 0x30u ) {
        _log("\tNetworkServiceProvider::CreateSession Error::Invalid Credential parameter\n");
        return 0x20;
    }
    if ( !a5_cred->f10_totalMaxPlayers ) {
        _log("\tNetworkServiceProvider::CreateSession Error::dwTotalMaxPlayers must be > 0\n");
        return 0x20;
    }
    memset(this->f5A_ackPacketCount_perPlayerSlot, 0, sizeof(this->f5A_ackPacketCount_perPlayerSlot));
    memset(this->fDA_unused1_perPlayerSlot, 0, sizeof(this->fDA_unused1_perPlayerSlot));
    MyPlayerDesc *f24_playerList = this->f24_playerList;
    this->f15A_ignored_inNewSession = 0;
    this->f15E_nextAckIdx = 0;
    this->f413_AckPacketsCountArr_idx = 0;
    if ( f24_playerList )
        net::_free(f24_playerList);
    MyPlayerDesc *v9_playerList = (MyPlayerDesc *) net::_malloc(sizeof(MyPlayerDesc) * a5_cred->f10_totalMaxPlayers);
    this->f24_playerList = v9_playerList;
    if ( !v9_playerList ) {
        _log("\tNetworkServiceProvider::CreateSession -:couldnot allocate for player list\n");
        return 0x20;
    }
    memset(v9_playerList, 0, 0x4F * a5_cred->f10_totalMaxPlayers);
    MyCurPlayerInfo *p_f226_curPlayer = &this->f226_curPlayer;
    memset(p_f226_curPlayer, 0, 0x2Cu);
    p_f226_curPlayer->f2C = 0;
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    if ( !this->CreateServiceProvider() ) {
        _log("\tNetworkServiceProvider::CreateSession Error::CouldNot Create Service Provider Thread\n");
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        return 0x20;
    }
    if ( !this->startSendDeliverThread() ) {
        _log("\tNetworkServiceProvider::CreateSession Error::CouldNot create System Events\n");
        this->destroyMainThread();
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        return 0x20;
    }
    if ( wcslen(a3_gameName) >= 0x1F )
        a3_gameName[31] = 0;
    if ( wcslen(a4_playerName) >= 0xF )
        a4_playerName[15] = 0;
    // bfnet=10001CE0 dplay=10006900
    int result;
    for ( result = this->CreateSPSession(a2_outPlayers, a3_gameName, a4_playerName, a5_cred, a6_flags);
          result == 1;  // connecting
          result = this->CreateSPSession(a2_outPlayers, a3_gameName, a4_playerName, a5_cred, a6_flags) ) {
        ;
    }
    if ( result == 2 ) {
        HANDLE f172_hEvent2 = this->f172_OnPlayerJoined_hEvent;
        this->f28_host_playerId = this->f226_curPlayer.playerId;
        SetEvent(f172_hEvent2);
        SetEvent(this->f16A_playerCountChange_hEvent);
        return 2;
    } else {
        this->destroySystemThread();
        this->destroyMainThread();
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
        memset(p_f226_curPlayer, 0, 0x2Cu);
        p_f226_curPlayer->f2C = 0;
        return result;
    }
}

int NetworkServiceProvider::GetAllPlayersInfo(DWORD *a2_outCurPlayerSlot) {
    int isSuccess = 0;
    unsigned int v4_idx = 0;
    int isOverflow = 0;
    int v9_found = 0;
    if (this->f226_curPlayer.isHost()) return TRUE;

    struct mmtime_tag startTime;
    timeGetSystemTime(&startTime, 0xCu);
    struct mmtime_tag v11_sysTime;
    memset(&v11_sysTime, 0, sizeof(v11_sysTime));
    struct mmtime_tag v12_sysTime;  // fixme: uninitialized
    v12_sysTime.u.ms = 0;
    while ( v4_idx < this->f186_sessionDesc.currentPlayers || !v9_found ) {
        if ( v12_sysTime.u.ms - v11_sysTime.u.ms >= 1000 ) {
            EnterCriticalSection(&this->dataLock);
            v4_idx = 0;
            for (int curSlot = 0; curSlot < this->f186_sessionDesc.totalMaxPlayers; ++curSlot) {
                MyPlayerDesc *curDesc = &this->f24_playerList[curSlot];
                if (!curDesc->isJoined()) continue;
                // not joined
                ++v4_idx;
                if (curDesc->f20_playerId_slot != this->f226_curPlayer.playerId) continue;
                this->f226_curPlayer.playersSlot = curSlot;
                v9_found = 1;
                *a2_outCurPlayerSlot = curSlot;
            }

            _log("NO PLAYERS = %d\n", v4_idx);
            if ( v4_idx < this->f186_sessionDesc.currentPlayers ) {
                isSuccess = isOverflow;
            } else {
                isSuccess = 1;
                isOverflow = 1;
            }
            LeaveCriticalSection(&this->dataLock);
            timeGetSystemTime(&v11_sysTime, 0xCu);
        }
        if ( !isSuccess ) {
            timeGetSystemTime(&v12_sysTime, 0xCu);
            struct mmtime_tag v13_sysTime;
            timeGetSystemTime(&v13_sysTime, 0xCu);
            if (v13_sysTime.u.ms - startTime.u.ms > (30 * 1000) )
                break;
        }
    }
    if ( isSuccess )
        return TRUE;
    _log("\tNetworkServiceProvider::GetAllPlayersInfo Error::CouldNot get PlayerList\n");
    return FALSE;
}

int NetworkServiceProvider::JoinSession(
        MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName,
        MySessionCredentials *a5_cred) {
    int result = 0x20;
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tNetworkServiceProvider::JoinSession Error::ServiceProvider Not Initialised\n");
        return result;
    }
    MyCurPlayerInfo *p_f226_curPlayer = &this->f226_curPlayer;
    if (this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::JoinSession Error::Already Connected To Session\n");
        return 0x20;
    }
    memset(this->f5A_ackPacketCount_perPlayerSlot, 0, sizeof(this->f5A_ackPacketCount_perPlayerSlot));
    memset(this->fDA_unused1_perPlayerSlot, 0, sizeof(this->fDA_unused1_perPlayerSlot));
    MyPlayerDesc *f24_playerList = this->f24_playerList;
    this->f15A_ignored_inNewSession = 0;
    this->f15E_nextAckIdx = 0;
    this->f413_AckPacketsCountArr_idx = 0;
    if ( f24_playerList )
        net::_free(f24_playerList);
    int f24_totalMaxPlayers = a2_desc->totalMaxPlayers;
    if ( !f24_totalMaxPlayers )
        f24_totalMaxPlayers = 1;
    unsigned int v9_playerList_size = sizeof(MyPlayerDesc) * f24_totalMaxPlayers;
    MyPlayerDesc *playerList = (MyPlayerDesc *) net::_malloc(sizeof(MyPlayerDesc) * f24_totalMaxPlayers);
    this->f24_playerList = playerList;
    if ( !playerList ) {
        _log("\tNetworkServiceProvider::JoinSession -:couldnot allocate for player list\n");
        return 0x20;
    }
    memset(playerList, 0, v9_playerList_size);
    memset(p_f226_curPlayer, 0, 0x2Cu);
    p_f226_curPlayer->f2C = 0;
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    if ( !this->CreateServiceProvider() ) {
        _log("\tNetworkServiceProvider::JoinSession Error::CouldNot Create Service Provider Thread\n");
        if (this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        return 0x20;
    }
    if ( !this->startSendDeliverThread() ) {
        _log("\tNetworkServiceProvider::JoinSession Error::CouldNot create System Events\n");
        this->destroyMainThread();
        if (this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        return 0x20;
    }
    if ( wcslen(a4_playerName) >= 0xF )
        a4_playerName[15] = 0;

    // bfnet=10001FC0 dplay=10006DB0
    for ( result = this->JoinSPSession(a2_desc, a3_outPlayerCount, a4_playerName, a5_cred);
          result == 1;  // connecting
          result = this->JoinSPSession(a2_desc, a3_outPlayerCount, a4_playerName, a5_cred) ) {
        ;
    }
    if ( result == 2 ) {  // joined
        SetEvent(this->f172_OnPlayerJoined_hEvent);
        if ( this->GetAllPlayersInfo(a3_outPlayerCount) )
            return result;
        _log("\tNetworkServiceProvider::JoinSession Error::CouldNot get PlayerList\n");
        this->Destroy();
        this->destroySystemThread();
        this->destroyMainThread();
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        return 0x20;
    }
    this->destroySystemThread();
    this->destroyMainThread();
    if ( this->f24_playerList ) {
        net::_free(this->f24_playerList);
        this->f24_playerList = NULL;
    }
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    memset(p_f226_curPlayer, 0, 0x2Cu);
    p_f226_curPlayer->f2C = 0;
    return result;
}

void ScheduledPacket_initWithPlayer(ScheduledPacket *self, NetworkServiceProvider *prov, uint16_t slotNo) {
    self->f4_ackPacketId = prov->f5A_ackPacketCount_perPlayerSlot[slotNo]++;
    self->fC__0 = 0;
    self->f10__60000 = 60000;
    self->f14_timeSendDelta = 1000;
    self->f18_lastSendTime = 0;
    self->f8_slotMask = 1 << slotNo;
    self->f24_pPacketStart = (PacketHeader *) &self[1];
}

void NetworkServiceProvider::schedulePlayersChangePacket(
        int a2_type, PlayerId a3_playerId_slot, int a4_playerSlot,
        wchar_t *a5_playerName, int a6_flags) {
    switch (a2_type) {
        case MyPacket_1_Create::ID: break;  // join
        case MyPacket_9_PlayerLeave::ID: break;  // player leave
        case MyPacket_E_NewHost::ID: break;  // new host
        default: return;
    }

    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
        MyPlayerDesc *curPlayer = &this->f24_playerList[i];
        if (!curPlayer->isJoined()) continue;
        if (curPlayer->f20_playerId_slot == this->f226_curPlayer.playerId ) continue;

        if ( a2_type == MyPacket_1_Create::ID ) {  // join
            #pragma pack(push, 1)
            struct ScheduledPacket_1_Create : public ScheduledPacket {
                MyPacket_1_Create f28_packet;
            };
            #pragma pack(pop)
            static_assert(sizeof(ScheduledPacket_1_Create) == 0xC3);
            auto *scheduled = (ScheduledPacket_1_Create *) net::_malloc(sizeof(ScheduledPacket_1_Create));
            if (scheduled == nullptr) continue;

            ScheduledPacket_initWithPlayer(scheduled, this, curPlayer->f35_slotNo);
            scheduled->f20_packetSize = sizeof(MyPacket_1_Create);
            scheduled->f28_packet.f0_hdr.signature = PacketHeader::MAGIC;
            scheduled->f28_packet.f0_hdr.packetTy = MyPacket_1_Create::ID;
            scheduled->f28_packet.fC_flags = a6_flags;
            scheduled->f28_packet.f10_ackPacketId = scheduled->f4_ackPacketId;
            scheduled->f28_packet.f2C_guidApplication = this->f186_sessionDesc.guidApplication;
            scheduled->f28_packet.f3C_guidInstance = this->f186_sessionDesc.guidInstance;
            scheduled->f28_packet.f14_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
            scheduled->f28_packet.f18_currentPlayers = this->f186_sessionDesc.currentPlayers;
            scheduled->f28_packet.f4C_playerDesc.f20_playerId_slot = a3_playerId_slot;
            scheduled->f28_packet.f4C_playerDesc.flags = 1;
            scheduled->f28_packet.f4C_playerDesc.f2C_packet_D_Guaranteed_sendScheduled_count = 0;
            scheduled->f28_packet.f4C_playerDesc.f30_receivedScheduled_count = 0;
            scheduled->f28_packet.f4C_playerDesc.field_24 = 0;
            scheduled->f28_packet.f4C_playerDesc.f35_slotNo = a4_playerSlot;
            scheduled->f28_packet.f4C_playerDesc.f36_subDesc = this->f24_playerList[a4_playerSlot].f36_subDesc;
            wcscpy(scheduled->f28_packet.f4C_playerDesc.f0_playername, a5_playerName);
            this->queuePacketToSend(scheduled);
            SetEvent(this->f16A_playerCountChange_hEvent);
        } else if ( a2_type == MyPacket_9_PlayerLeave::ID ) {  // player leave
            struct ScheduledPacket_9_PlayerLeave : public ScheduledPacket{
                MyPacket_9_PlayerLeave f28_packet;
            };
            static_assert(sizeof(ScheduledPacket_9_PlayerLeave) == 0x88);
            auto *scheduled = (ScheduledPacket_9_PlayerLeave *) net::_malloc(sizeof(ScheduledPacket_9_PlayerLeave));
            if (scheduled == nullptr) continue;

            ScheduledPacket_initWithPlayer(scheduled, this, curPlayer->f35_slotNo);
            scheduled->f20_packetSize = sizeof(MyPacket_9_PlayerLeave);
            scheduled->f28_packet.f0_hdr.signature = PacketHeader::MAGIC;
            scheduled->f28_packet.f0_hdr.packetTy = MyPacket_9_PlayerLeave::ID;
            scheduled->f28_packet.fC_flags = a6_flags;
            scheduled->f28_packet.f10_ackPacketId = scheduled->f4_ackPacketId;
            scheduled->f28_packet.f14_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
            scheduled->f28_packet.f18_currentPlayers = this->f186_sessionDesc.currentPlayers;
            scheduled->f28_packet.f2C_guidApplication = this->f186_sessionDesc.guidApplication;
            scheduled->f28_packet.f3C_guidInstance = this->f186_sessionDesc.guidInstance;
            scheduled->f28_packet.f5C_playerId = a3_playerId_slot;
            this->queuePacketToSend(scheduled);
            SetEvent(this->f16A_playerCountChange_hEvent);
        } else if ( a2_type == MyPacket_E_NewHost::ID ) {  // new host
#pragma pack(push, 1)
            struct ScheduledPacket_E_NewHost : public ScheduledPacket {
                MyPacket_E_NewHost f28_packet;
            };
#pragma pack(pop)
            static_assert(sizeof(ScheduledPacket_E_NewHost) == 0xDB);
            auto *scheduled = (ScheduledPacket_E_NewHost *) net::_malloc(sizeof(ScheduledPacket_E_NewHost));
            if (scheduled == nullptr) continue;

            ScheduledPacket_initWithPlayer(scheduled, this, curPlayer->f35_slotNo);
            scheduled->f20_packetSize = sizeof(MyPacket_E_NewHost);
            scheduled->f28_packet.f0_hdr.signature = PacketHeader::MAGIC;
            scheduled->f28_packet.f0_hdr.packetTy = MyPacket_E_NewHost::ID;
            scheduled->f28_packet.fC_flags = a6_flags;
            scheduled->f28_packet.f10_ackPacketId = scheduled->f4_ackPacketId;
            scheduled->f28_packet.f1C_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
            scheduled->f28_packet.f20_currentPlayers = this->f186_sessionDesc.currentPlayers;
            scheduled->f28_packet.f34_guidApplication = this->f186_sessionDesc.guidApplication;
            scheduled->f28_packet.f44_guidInstance = this->f186_sessionDesc.guidInstance;
            scheduled->f28_packet.f88__17 = 17;
            scheduled->f28_packet.f74_playerId = a3_playerId_slot;
            scheduled->f28_packet.f89_playerSlot = a4_playerSlot;
            scheduled->f28_packet.f8A_subDesc = this->f24_playerList[a4_playerSlot].f36_subDesc;
            wcscpy(scheduled->f28_packet.f54_playerName, a5_playerName);
            this->queuePacketToSend(scheduled);
            SetEvent(this->f16A_playerCountChange_hEvent);
        }
    }
}

void NetworkServiceProvider::queuePacketToSend(ScheduledPacket *toAdd) {
    if ( toAdd ) {
        toAdd->f0_next = NULL;
        ScheduledPacket *last = NULL;
        for (ScheduledPacket *cur = this->f337_packetSendQueue; cur; cur = cur->f0_next) last = cur;
        if (last) {
            last->f0_next = toAdd;
        } else {
            this->f337_packetSendQueue = toAdd;
        }
    }

    for (int i = 0; i < 50; ++i) {
        if (this->f26F_packetSendToAllArr[i] != NULL) continue;
        if (this->f337_packetSendQueue == NULL) continue;
        this->f26F_packetSendToAllArr[i] = this->f337_packetSendQueue;
        struct mmtime_tag sysTime;
        timeGetSystemTime(&sysTime, 0xCu);
        this->f26F_packetSendToAllArr[i]->f1C_addedTime = sysTime.u.ms;
        this->f337_packetSendQueue = this->f337_packetSendQueue->f0_next;
    }
}

void NetworkServiceProvider::send_B_PlayerList(int a2_slot) {
    unsigned int v3_mod = this->f186_sessionDesc.currentPlayers % 5u;
    unsigned int v6_playerIdx = 0;
    unsigned int v5_div = this->f186_sessionDesc.currentPlayers / 5u;
    if ( v3_mod )
        ++v5_div;
    if (!v5_div) return;
    for (int i = 0; i < v5_div; ++i) {
        ScheduledPacket_B_PlayerList *scheduled = (ScheduledPacket_B_PlayerList *) net::_malloc(sizeof(ScheduledPacket_B_PlayerList));
        if (!scheduled) continue;
        scheduled->f4_ackPacketId = this->f5A_ackPacketCount_perPlayerSlot[a2_slot]++;
        scheduled->fC__0 = 0;
        scheduled->f10__60000 = 60000;
        scheduled->f14_timeSendDelta = 1000;
        scheduled->f18_lastSendTime = 0;
        scheduled->f20_packetSize = sizeof(MyPacket_B_PlayerList);
        scheduled->f24_pPacketStart = &scheduled->f28_packet.f0_hdr;
        scheduled->f8_slotMask = 1 << a2_slot;
        scheduled->f28_packet.f0_hdr.signature = PacketHeader::MAGIC;
        scheduled->f28_packet.f0_hdr.packetTy = MyPacket_B_PlayerList::ID;
        scheduled->f28_packet.fC_ackPacketId = scheduled->f4_ackPacketId;
        scheduled->f28_packet.f10_playerId = this->f226_curPlayer.playerId;
        scheduled->f28_packet.f14_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
        scheduled->f28_packet.f18_currentPlayers = this->f186_sessionDesc.currentPlayers;
        scheduled->f28_packet.f2C_playerDescCount = 0;
        int j = 0;
        for (; v6_playerIdx < this->f186_sessionDesc.totalMaxPlayers; ++v6_playerIdx) {
            MyPlayerDesc *curDesc = &this->f24_playerList[v6_playerIdx];
            if (!curDesc->isJoined()) continue;  // not joined
            scheduled->f28_packet.f30_MyPlayerDesc_arr[j++] = *curDesc;
            ++scheduled->f28_packet.f2C_playerDescCount;
            if(j >= 5) break;
        }
        this->queuePacketToSend(scheduled);
    }
}

void NetworkServiceProvider::releasePacketSendArr() {
    for (int i = 0; i < 50; ++i) {
        ScheduledPacket *entry = this->f26F_packetSendToAllArr[i];
        if (!entry) continue;
        net::_free(entry);
        this->f26F_packetSendToAllArr[i] = NULL;
    }
}

void NetworkServiceProvider::releasePacketSendArr_forPlayer(char a2_slotId) {
    int slotMask = 1 << a2_slotId;
    if (slotMask == 0) return;
    for (int i = 0; i < 50; ++i) {
        ScheduledPacket *sched = this->f26F_packetSendToAllArr[i];
        if (sched == NULL) continue;
//            if (!(slotMask * sched->f8_slotMask)) continue;
        if (sched->f8_slotMask == 0) continue;
        int v4_slotMask = sched->f8_slotMask & ~slotMask;
        sched->f8_slotMask = v4_slotMask;
        if (v4_slotMask != 0) continue;
        net::_free(sched);
        this->f26F_packetSendToAllArr[i] = NULL;
    }
}

void NetworkServiceProvider::handlePacket_C(MyPacket_C_HandledPackets *a2_packet) {
    uint16_t v3_slotIdx = 0;
    MyPlayerDesc *found = NULL;
    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i, ++v3_slotIdx) {
        MyPlayerDesc *curDesc = &this->f24_playerList[i];
        if (a2_packet->playerId != curDesc->f20_playerId_slot) continue;
        found = curDesc;
        break;
    }
    if (found == NULL) {
        patch::log::err("player not found for MyPacket_C_HandledPackets");
        return;
    }
    char v8_slotIdx = v3_slotIdx;
    MyPlayerDesc *playerDesc = &this->f24_playerList[v3_slotIdx];
    if (!playerDesc->isJoined()) {
        patch::log::err("player is not joined");
        return;
    }
    if (a2_packet->playerId != playerDesc->f20_playerId_slot) {
        patch::log::err("player id missmatch");
        return;
    }
    for (int i = 0; i < 50; ++i) {
        DWORD handledPacketId = a2_packet->AckPacketsCountArr[i];
        for (int j = 0; j < 50; ++j) {
            ScheduledPacket *sched = this->f26F_packetSendToAllArr[j];
            if (sched == NULL) continue;
            if (((1 << v8_slotIdx) & sched->f8_slotMask) == 0) continue;
            if (sched->f4_ackPacketId != handledPacketId) continue;
            net::_free(sched);
            this->f26F_packetSendToAllArr[j] = NULL;
        }
    }
}

void NetworkServiceProvider::releaseToHandleList() {
    MLDPLAY_SYSTEMQUEUE_Entry *cur = this->f257_toHandleList.first;
    while ( cur ) {
        MLDPLAY_SYSTEMQUEUE_Entry *toFree = cur;
        cur = cur->next;
        net::_free(toFree);
    }
    this->f257_toHandleList.first = NULL;
    this->f257_toHandleList.last = NULL;
}

int NetworkServiceProvider::handlePacket_1_2_9_B_E(PacketHeader *packet, unsigned int a3_size, MySocket *a4_sock) {
    unsigned int v19__slotPacketCount = 0;
    int v22__slotPacketCount = 0;
    int v20_addPacketToHandelList = 0;
    int v21_syncAckCounts = 0;
    if (!this->f226_curPlayer.isConnectedToSession()) return 0;
    if (this->f226_curPlayer.isHost()) return 0;
    if ( a3_size < sizeof(PacketHeader) || packet->signature != PacketHeader::MAGIC ) return 0;
    int v23_returnPacketHandled = 0;
    switch ( packet->packetTy ) {
        case MyPacket_1_Create::ID: {
            MyPacket_1_Create *a2_packet = (MyPacket_1_Create *) packet;
            v23_returnPacketHandled = 1;
            if (a3_size < sizeof(MyPacket_1_Create)
                || a2_packet->f2C_guidApplication != this->f44_guidApplication
                || a2_packet->f3C_guidInstance != this->f186_sessionDesc.guidInstance
                    ) break;
            v19__slotPacketCount = a2_packet->f10_ackPacketId;
            v22__slotPacketCount = v19__slotPacketCount;
            v20_addPacketToHandelList = 1;
            v21_syncAckCounts = 1;
        } break;
        case MyPacket_2_SessionLost::ID:
            v23_returnPacketHandled = 1;
            break;
        case MyPacket_9_PlayerLeave::ID: {
            v23_returnPacketHandled = 1;
            MyPacket_9_PlayerLeave *a2_packet = (MyPacket_9_PlayerLeave *) packet;
            if (a3_size < sizeof(MyPacket_9_PlayerLeave)
                || a2_packet->f2C_guidApplication != this->f44_guidApplication
                || a2_packet->f3C_guidInstance != this->f186_sessionDesc.guidInstance
                    ) break;
            v21_syncAckCounts = 1;
            for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
                MyPlayerDesc *curDesc = &this->f24_playerList[i];
                if (!curDesc->isJoined()
                    || curDesc->f20_playerId_slot != a2_packet->f5C_playerId) {
                    continue;
                }
                if (i == 0)
                    _log("HOST IS LEAVING SO I MUST SEND X AMOUNT OF ACKS\n");
                unsigned int f15E_nextAckIdx = this->f15E_nextAckIdx;
                if (a2_packet->f10_ackPacketId >= f15E_nextAckIdx) {
                    v19__slotPacketCount = a2_packet->f10_ackPacketId;
                    v22__slotPacketCount = v19__slotPacketCount;
                    v20_addPacketToHandelList = 1;
                }
                if (a2_packet->f4C_guidPlayer == this->f34_guidPlayer &&
                    a2_packet->f5C_playerId == this->f226_curPlayer.playerId
                        ) {
                    a2_packet->f10_ackPacketId = f15E_nextAckIdx;
                    v19__slotPacketCount = this->f15E_nextAckIdx;
                    v22__slotPacketCount = v19__slotPacketCount;
                    this->releaseToHandleList();
                    v21_syncAckCounts = 0;
                    v20_addPacketToHandelList = 1;
                }
                break;
            }
        } break;
        case MyPacket_B_PlayerList::ID: {
            MyPacket_B_PlayerList *a2_packet = (MyPacket_B_PlayerList *) packet;
            v23_returnPacketHandled = 1;
            if (a3_size < sizeof(MyPacket_B_PlayerList)) break;
            v19__slotPacketCount = a2_packet->fC_ackPacketId;
            v22__slotPacketCount = v19__slotPacketCount;
            v20_addPacketToHandelList = 1;
            v21_syncAckCounts = 1;
            if ((this->f186_sessionDesc.flags & 4) != 0) {
                this->f28_host_playerId = a2_packet->f10_playerId;
            }
        } break;
        case MyPacket_E_NewHost::ID: {
            MyPacket_E_NewHost *a2_packet = (MyPacket_E_NewHost *) packet;
            v23_returnPacketHandled = 1;
            if (a3_size < sizeof(MyPacket_E_NewHost)
                || a2_packet->f34_guidApplication != this->f44_guidApplication
                || a2_packet->f44_guidInstance != this->f186_sessionDesc.guidInstance
                    ) break;
            v21_syncAckCounts = 1;
            this->f28_host_playerId = a2_packet->f74_playerId;
            int f10_ackPacketId = a2_packet->f10_ackPacketId;
            this->f15E_nextAckIdx = f10_ackPacketId;
            v22__slotPacketCount = f10_ackPacketId;
            v19__slotPacketCount = f10_ackPacketId;
            v20_addPacketToHandelList = 1;
            this->releaseToHandleList();
        } break;
        default:
            break;
    }
    if ( v20_addPacketToHandelList ) {
        if ( v19__slotPacketCount >= this->f15E_nextAckIdx ) {
            MLDPLAY_SYSTEMQUEUE_Entry *newEntry = (MLDPLAY_SYSTEMQUEUE_Entry *) net::_malloc(sizeof(MLDPLAY_SYSTEMQUEUE_Entry) + a3_size);
            if ( newEntry ) {
                memcpy(&newEntry[1], packet, a3_size);
                newEntry->prev = NULL;
                newEntry->next = NULL;
                newEntry->dataSize = a3_size;
                newEntry->pData = &newEntry[1];
                newEntry->_slotPacketCount = v19__slotPacketCount;
                if (!this->f257_toHandleList.first) {
                    this->f257_toHandleList.first = newEntry;
                    this->f257_toHandleList.last = newEntry;
                } else {
                    MLDPLAY_SYSTEMQUEUE_Entry *last = NULL;
                    for (MLDPLAY_SYSTEMQUEUE_Entry *cur = this->f257_toHandleList.first; cur; cur = cur->next) {
                        last = cur;
                        if (v19__slotPacketCount >= cur->_slotPacketCount) continue;
                        newEntry->next = cur;
                        newEntry->prev = cur->prev;
                        cur->prev = newEntry;
                        if (newEntry->prev) this->f257_toHandleList.first = newEntry;
                        last = NULL;
                        break;
                    }
                    if(last != NULL) {
                        last->next = newEntry;
                        newEntry->prev = last;
                        newEntry->next = NULL;
                        this->f257_toHandleList.last = newEntry;
                    }
                }
            }
        }
    }
    if ( !v21_syncAckCounts )
        return v23_returnPacketHandled;
    this->f33B_packet.hdr.playersSlot = this->f226_curPlayer.playersSlot;
    this->f33B_packet.playerId = this->f226_curPlayer.playerId;
    this->f33B_packet.hdr.signature = PacketHeader::MAGIC;
    this->f33B_packet.hdr.playerListIdx_m1_m2 = net_HostPlayer;
    this->f33B_packet.hdr.f2 = 0;
    this->f33B_packet.hdr.packetTy = MyPacket_C_HandledPackets::ID;
    this->f33B_packet.AckPacketsCountArr[this->f413_AckPacketsCountArr_idx] = v22__slotPacketCount;
    if ( this->f413_AckPacketsCountArr_idx >= 50u )
        this->f413_AckPacketsCountArr_idx = 0;
    this->SendMessageTo(a4_sock, &this->f33B_packet, sizeof(MyPacket_C_HandledPackets), 0);
    return v23_returnPacketHandled;
}

void NetworkServiceProvider::processSPMessages() {
    int v26_exitLoop = 0;
    int v24_handleMessage = 0;
    PlayerId f20_playerId_slot = {0};
    MyMessage_1_AddedPlayer v27_message;
    while ( !v26_exitLoop ) {
        PacketHeader *v2_packet = (PacketHeader *)this->ReadSPMessage();
        if (!v2_packet) {
            v26_exitLoop = 1;
            continue;
        }
        switch (v2_packet->packetTy) {
            case MyPacket_1_Create::ID: {
                MyPacket_1_Create *packet = (MyPacket_1_Create *) v2_packet;
                EnterCriticalSection(&this->dataLock);
                this->f186_sessionDesc.currentPlayers = packet->f18_currentPlayers;
                this->f186_sessionDesc.totalMaxPlayers = packet->f14_totalMaxPlayers;
                int f4_slot = packet->f4C_playerDesc.f35_slotNo;
                this->f24_playerList[f4_slot] = packet->f4C_playerDesc;
                _log("ADDED NEW PLAYER ID %d index %d\n", packet->f4C_playerDesc.f20_playerId_slot, f4_slot);
                MyPlayerDesc *f24_playerList = this->f24_playerList;
                v27_message.f0_message = v27_message.f0_message & 0xF0 | 1;
                v27_message.f5_slotNo = f4_slot;
                v27_message.f26_playerId_slot = packet->f4C_playerDesc.f20_playerId_slot;
                wcscpy(v27_message.f6_playerName, f24_playerList[f4_slot].f0_playername);
                LeaveCriticalSection(&this->dataLock);
                this->messageHandler(net_HostPlayer, &v27_message, 0x2A, 1, this->f4_arg);
            }
                break;
            case MyPacket_2_SessionLost::ID:
                _log("SESSION LOST\n");
                break;
            case MyPacket_3_Data::ID: {
                int size;
                this->_handleMessage(v2_packet, 4u, &size);
            }
                break;
            case MyPacket_4_ChatMessage::ID: {
                int size;
                this->_handleMessage(v2_packet, 6u, &size);
            }
                break;
            case MyPacket_9_PlayerLeave::ID: {
                MyPacket_9_PlayerLeave *packet = (MyPacket_9_PlayerLeave *) v2_packet;
                EnterCriticalSection(&this->dataLock);
                for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
                    MyPlayerDesc *curDesc = &this->f24_playerList[i];
                    if (!curDesc->isJoined()) continue;
                    if (curDesc->f20_playerId_slot != packet->f5C_playerId) continue;
                    int f35SlotNo = curDesc->f35_slotNo;
                    v24_handleMessage = 1;
                    this->fDA_unused1_perPlayerSlot[f35SlotNo] = 0;
                    this->f5A_ackPacketCount_perPlayerSlot[curDesc->f35_slotNo] = 0;
                    f20_playerId_slot = curDesc->f20_playerId_slot;
                    _log("\tBullfrogNET::DESTROYING PLAYER Index %d\n", packet->f5C_playerId);
                    memset(curDesc, 0, sizeof(MyPlayerDesc));
                    this->f186_sessionDesc.currentPlayers = packet->f18_currentPlayers;
                    this->f186_sessionDesc.totalMaxPlayers = packet->f14_totalMaxPlayers;
                    break;
                }
                if (packet->f5C_playerId == this->f226_curPlayer.playerId) {
                    _log("\tBullfrogNET::Destroying My player\n");
                    this->f226_curPlayer.flags &= ~2;
                }
                LeaveCriticalSection(&this->dataLock);
                if (v24_handleMessage)
                    this->messageHandler(net_HostPlayer, &f20_playerId_slot, 4, 2, this->f4_arg);
            }
                break;
            case MyPacket_B_PlayerList::ID: {
                MyPacket_B_PlayerList *packet = (MyPacket_B_PlayerList *) v2_packet;
                EnterCriticalSection(&this->dataLock);
                this->f186_sessionDesc.currentPlayers = packet->f18_currentPlayers;
                this->f186_sessionDesc.totalMaxPlayers = packet->f14_totalMaxPlayers;
                for (int i = 0; i < packet->f2C_playerDescCount; ++i) {
                    MyPlayerDesc *desc = &packet->f30_MyPlayerDesc_arr[i];
                    int slot = desc->f35_slotNo;
                    this->f24_playerList[slot] = *desc;
                    this->f24_playerList[slot].f2C_packet_D_Guaranteed_sendScheduled_count = 0;
                    this->f24_playerList[slot].f30_receivedScheduled_count = 0;
                }
                LeaveCriticalSection(&this->dataLock);
            }
                break;
            case MyPacket_D_Guaranteed::ID:
                this->handlePacket_D((MyPacket_D_Guaranteed *) v2_packet);
                break;
            case MyPacket_E_NewHost::ID: {
                MyPacket_E_NewHost *packet = (MyPacket_E_NewHost *) v2_packet;
                EnterCriticalSection(&this->dataLock);
                if(this->f24_playerList) {
                    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
                        MyPlayerDesc *v16_curDesc = &this->f24_playerList[i];
                        if (!v16_curDesc->isJoined()) continue;
                        if (!v16_curDesc->isHost()) continue;
                        v16_curDesc->flags &= 0xFu;
                    }
                    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
                        MyPlayerDesc *curDesc = &this->f24_playerList[i];
                        if (!curDesc->isJoined()) continue;
                        if (curDesc->f20_playerId_slot != packet->f74_playerId) continue;
                        curDesc->flags = curDesc->flags & 0xF | 0x10;
                        this->f186_sessionDesc.currentPlayers = packet->f20_currentPlayers;
                        this->f186_sessionDesc.totalMaxPlayers = packet->f1C_totalMaxPlayers;
                        this->setNewHost(packet);
                        break;
                    }
                }
                LeaveCriticalSection(&this->dataLock);
                _log("NEW HOST\n");
            }
                break;
            case MyPacket_10_GuaranteedProgress::ID:
                EnterCriticalSection(&this->dataLock);
                this->handlePacket_10((MyPacket_10_GuaranteedProgress *) v2_packet);
                LeaveCriticalSection(&this->dataLock);
                break;
            default:
                break;
        }
    }
}

void NetworkServiceProvider::handlePacket_D_locked(MyPacket_D_Guaranteed *a2_packet) {
    int f4_playersSlot = a2_packet->f0_hdr.playersSlot;
    if ((unsigned int) (unsigned __int16) f4_playersSlot >= this->f186_sessionDesc.totalMaxPlayers) return;
    MyPlayerDesc *v5_playerDesc = &this->f24_playerList[f4_playersSlot];
    if (!v5_playerDesc->isJoined()) return;
    if (v5_playerDesc->f20_playerId_slot != a2_packet->f1C_playerId) return;
    if ( a2_packet->f20_playerId_slot != this->f226_curPlayer.playerId ) {
        this->SendMessage(a2_packet->f20_playerId_slot, a2_packet, sizeof(MyPacket_D_Guaranteed) + 0x1A4, 0);  // 0x1F0
        return;
    }
    int noEntriesLeft = 0;
    int doSendProgressPacket = 0;

    MyPacket_10_GuaranteedProgress v50_packet;
    MLDPLAY_SYSTEMQUEUE_Entry *receivedQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(&this->f267_receivedDeliverQueue);
    if ( receivedQueue_entry ) {
        int f34_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
        if ( a2_packet->f28_sendScheduled_idx < v5_playerDesc->f30_receivedScheduled_count ) {
            int f38_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
            v50_packet.f1C_blocksChunk_startIdx = f34_blocksChunk_startIdx;
            v50_packet.f20_maxPartsCount = f38_maxPartsCount;
            *(DWORD *)v50_packet.f24_recvdArr = 0100200401;
            *(DWORD *)&v50_packet.f24_recvdArr[4] = 0100200401;
            doSendProgressPacket = 1;
        } else {
            MyReceivedHeader *v9_recvdHeader;
            for (; receivedQueue_entry; receivedQueue_entry = receivedQueue_entry->next) {
                v9_recvdHeader = (MyReceivedHeader *) receivedQueue_entry->pData;
                if (v9_recvdHeader->f10_maxPartsCount != a2_packet->f38_transferedPartsCount_max) continue;
                if (v9_recvdHeader->fC_blocksChunk_startIdx != f34_blocksChunk_startIdx) continue;
                if (v9_recvdHeader->f0__guaranteedIdx != a2_packet->f24_guaranteedCount) continue;
                if (v9_recvdHeader->f8_playerId_slot != v5_playerDesc->f20_playerId_slot) continue;
                if (v9_recvdHeader->f4__recv_sendScheduled_idx != a2_packet->f28_sendScheduled_idx) continue;

                if ( v9_recvdHeader->f14_partSize >= v9_recvdHeader->f18_totalSize ) {
                    v50_packet.f1C_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
                    int v42_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
                    v50_packet.f20_maxPartsCount = v42_maxPartsCount;
                    *(DWORD *)v50_packet.f24_recvdArr = 0x1010101;
                    *(DWORD *)&v50_packet.f24_recvdArr[4] = 0x1010101;
                } else {
                    int v10_relIdx = a2_packet->f48_blockIdx - f34_blocksChunk_startIdx;
                    if ( !v9_recvdHeader->f1C_recvdArr[v10_relIdx] ) {
                        v9_recvdHeader->f1C_recvdArr[v10_relIdx] = 1;
                        v9_recvdHeader->f14_partSize += a2_packet->f30_partSize;
                        memcpy(
                                &v9_recvdHeader->f1C_recvdArr[0x1A4 * a2_packet->f48_blockIdx + 8],
                                &a2_packet[1],
                                a2_packet->f30_partSize);
                    }
                    int v11_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
                    v50_packet.f1C_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
                    char *f1C_recvdArr = v9_recvdHeader->f1C_recvdArr;
                    v50_packet.f20_maxPartsCount = v11_maxPartsCount;
                    int v13_totalRecvdSize = 0;
                    memcpy(v50_packet.f24_recvdArr, v9_recvdHeader->f1C_recvdArr, 8);
                    int fC_blocksChunk_startIdx = v9_recvdHeader->fC_blocksChunk_startIdx;
                    if ( fC_blocksChunk_startIdx )
                        v13_totalRecvdSize = 420 * fC_blocksChunk_startIdx - 0x1A4;
                    for (unsigned int j = 0; j < 8; ++j ) {
                        if ( f1C_recvdArr[j] )
                            v13_totalRecvdSize += 0x1A4;
                    }
                    unsigned int _i = 0;
                    unsigned int v17_recvdCount = 0;
                    do {
                        if ( f1C_recvdArr[_i] )
                            ++v17_recvdCount;
                        ++_i;
                    } while ( _i < 8 );
                    if ( v17_recvdCount >= 8 ) {
                        unsigned int v18_sizeLeft = v9_recvdHeader->f18_totalSize - v13_totalRecvdSize;
                        int v19_maxPartsCount_plus1 = v9_recvdHeader->f10_maxPartsCount + 1;
                        v9_recvdHeader->fC_blocksChunk_startIdx = v19_maxPartsCount_plus1;
                        if ( v18_sizeLeft <= 0x1A4 ) {
                            v9_recvdHeader->f10_maxPartsCount = v19_maxPartsCount_plus1;
                            memset(v9_recvdHeader->f1C_recvdArr, 0, 8);
                        } else {
                            unsigned int v20_partsLeft = v18_sizeLeft / 0x1A4;
                            if ( v18_sizeLeft % 0x1A4 )
                                ++v20_partsLeft;
                            if ( v20_partsLeft <= 8 ) {
                                v9_recvdHeader->f10_maxPartsCount = v20_partsLeft + v19_maxPartsCount_plus1 - 1;
                            } else {
                                v9_recvdHeader->f10_maxPartsCount = v19_maxPartsCount_plus1 + 7;
                            }
                            memset(v9_recvdHeader->f1C_recvdArr, 0, 8);
                        }
                    }
                }
                doSendProgressPacket = 1;
                break;
            }
            if (!receivedQueue_entry) {
                noEntriesLeft = 1;
            }
        }
    } else {
        noEntriesLeft = 1;
    }
    if ( noEntriesLeft ) {
        if ( a2_packet->f28_sendScheduled_idx < v5_playerDesc->f30_receivedScheduled_count ) {
            int v25_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
            v50_packet.f1C_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
            // every block in chunk is received
            v50_packet.f20_maxPartsCount = v25_maxPartsCount;
            memset(v50_packet.f24_recvdArr, 1, 8);
            doSendProgressPacket = 1;
        } else if ( !a2_packet->f48_blockIdx ) {
            MyReceivedHeader *v22_recvdHeader = (MyReceivedHeader *) net::_malloc(sizeof(MyReceivedHeader) + a2_packet->f30_partSize);
            if ( v22_recvdHeader ) {
                v22_recvdHeader->f0__guaranteedIdx = a2_packet->f24_guaranteedCount;
                v22_recvdHeader->f4__recv_sendScheduled_idx = a2_packet->f28_sendScheduled_idx;
                v22_recvdHeader->f8_playerId_slot = v5_playerDesc->f20_playerId_slot;
                v22_recvdHeader->fC_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
                v22_recvdHeader->f10_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
                v22_recvdHeader->f14_partSize = a2_packet->f30_partSize;
                v22_recvdHeader->f18_totalSize = a2_packet->f2C_totalSize;
                memset(v22_recvdHeader->f1C_recvdArr, 0, 8);
                v22_recvdHeader->f1C_recvdArr[0] = 1;
                memcpy(&v22_recvdHeader->f24_data, &a2_packet[1], a2_packet->f30_partSize);
                if ( MLDPLAY_SYSTEMQUEUE::addEntry(
                        &this->f267_receivedDeliverQueue,
                        v22_recvdHeader,
                        sizeof(MyReceivedHeader) + a2_packet->f30_partSize,
                        sizeof(MyReceivedHeader) + a2_packet->f2C_totalSize) ) {
                    int v24_maxPartsCount = a2_packet->f38_transferedPartsCount_max;
                    v50_packet.f1C_blocksChunk_startIdx = a2_packet->f34_blocksChunk_startIdx;
                    v50_packet.f20_maxPartsCount = v24_maxPartsCount;
                    doSendProgressPacket = 1;
                    memcpy(v50_packet.f24_recvdArr, v22_recvdHeader->f1C_recvdArr, 8);
                }
                net::_free(v22_recvdHeader);
            }
        }
    }
    if ( doSendProgressPacket ) {
        v50_packet.f0_hdr.playerListIdx_m1_m2 = a2_packet->f0_hdr.playersSlot;
        v50_packet.f0_hdr.playersSlot = this->f226_curPlayer.playersSlot;
        v50_packet.fC_playerId_slot = this->f226_curPlayer.playerId;
        v50_packet.f14_guaranteedCount = a2_packet->f24_guaranteedCount;
        v50_packet.f0_hdr.signature = PacketHeader::MAGIC;
        v50_packet.f0_hdr.f2 = 0;
        v50_packet.f0_hdr.packetTy = MyPacket_10_GuaranteedProgress::ID;
        v50_packet.f0_hdr.f8_messageSize = sizeof(MyPacket_10_GuaranteedProgress) - sizeof(PacketHeader);
        v50_packet.f10_playerId = a2_packet->f1C_playerId;
        v50_packet.f18_sendScheduled_idx = a2_packet->f28_sendScheduled_idx;
        this->SendMessage(v5_playerDesc->f20_playerId_slot, &v50_packet, sizeof(MyPacket_10_GuaranteedProgress), 0);
    }
    int entryWasRemoved;
    do {
        entryWasRemoved = 0;
        for (MLDPLAY_SYSTEMQUEUE_Entry *entry = MLDPLAY_SYSTEMQUEUE::getFirst(&this->f267_receivedDeliverQueue); entry; entry = entry->next) {
            MyReceivedHeader *f10_recvdHeader = (MyReceivedHeader *)entry->pData;
            size_t v34_totalSize = f10_recvdHeader->f18_totalSize;
            if (f10_recvdHeader->f14_partSize < v34_totalSize) continue;
            MyPlayerDesc *f24_playerList = this->f24_playerList;
            int f24_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
            MyPlayerDesc *playerList_end = &f24_playerList[f24_totalMaxPlayers];
            for (; f24_playerList < playerList_end; ++f24_playerList ) {
                if (!f24_playerList->isJoined()) continue;
                if (f24_playerList->f20_playerId_slot != f10_recvdHeader->f8_playerId_slot) continue;
                break;
            }
            if (f24_playerList->f20_playerId_slot != f10_recvdHeader->f8_playerId_slot) continue;
            if (f24_playerList->f30_receivedScheduled_count != f10_recvdHeader->f4__recv_sendScheduled_idx) continue;
            MyGuarateedData *v38_msgGuaranteed = (MyGuarateedData *) net::_malloc(sizeof(MyGuarateedData) + v34_totalSize);
            char *v39_msgGuaranteed = (char *)v38_msgGuaranteed;
            if ( v38_msgGuaranteed ) {
                int v40_guaranteedIdx = f10_recvdHeader->f0__guaranteedIdx;
                v38_msgGuaranteed->f4_type = 1;   // 1: part success
                v38_msgGuaranteed->f0_guaranteedIdx = v40_guaranteedIdx;
                v38_msgGuaranteed->f8_pMsgLog = NULL;
                memcpy(&v38_msgGuaranteed[1], &f10_recvdHeader->f24_data, f10_recvdHeader->f18_totalSize);
                LeaveCriticalSection(&this->dataLock);
                this->messageHandler(
                        f24_playerList->f35_slotNo,
                        v39_msgGuaranteed,
                        f10_recvdHeader->f18_totalSize + 0xC,
                        5,
                        this->f4_arg);
                EnterCriticalSection(&this->dataLock);
                MLDPLAY_SYSTEMQUEUE::removeEntry(&this->f267_receivedDeliverQueue, entry);
                entryWasRemoved = 1;
                ++f24_playerList->f30_receivedScheduled_count;
                net::_free(v39_msgGuaranteed);
                break;
            }
        }
    } while(entryWasRemoved);
}

void NetworkServiceProvider::handlePacket_D(MyPacket_D_Guaranteed *a2_packet) {
    if (!a2_packet) return;
    if (!this->f226_curPlayer.isConnectedToSession()) return;
    EnterCriticalSection(&this->dataLock);
    handlePacket_D_locked(a2_packet);
    LeaveCriticalSection(&this->dataLock);
}

void NetworkServiceProvider::handlePacket_10_handleData() {
    MLDPLAY_SYSTEMQUEUE *p_f25F_deliverHeadersQueue = &this->f25F_deliverHeadersQueue;
    MLDPLAY_SYSTEMQUEUE_Entry *deliverHeadersQueue_entry_1 = MLDPLAY_SYSTEMQUEUE::getFirst(p_f25F_deliverHeadersQueue);
    if ( !deliverHeadersQueue_entry_1 ) return;
    MyDeliverHeader *f10_deliverHeader_1;
    while (true) {
        f10_deliverHeader_1 = (MyDeliverHeader *)deliverHeadersQueue_entry_1->pData;
        if ( f10_deliverHeader_1 ) {
            if ( (unsigned int)(f10_deliverHeader_1->f18_fullySentData + f10_deliverHeader_1->f14_counter2) >= f10_deliverHeader_1->f10_numPlayersToSend )
                break;
        }
        deliverHeadersQueue_entry_1 = deliverHeadersQueue_entry_1->next;
        if ( !deliverHeadersQueue_entry_1 )
            return;
    }
    if ( f10_deliverHeader_1->f44_fullDataToSend )
        net::_free(f10_deliverHeader_1->f44_fullDataToSend);
    if ( (f10_deliverHeader_1->f8_flags & 1) == 0 ) {
        MyGuarateedData_MsgLog *v25_message_5 = (MyGuarateedData_MsgLog *) net::_malloc(sizeof(MyGuarateedData_MsgLog));
        MyGuarateedData_MsgLog *message_5 = v25_message_5;
        if ( v25_message_5 ) {
            MyMsgLog *p_log = &v25_message_5->log;
            v25_message_5->hdr.f8_pMsgLog = &v25_message_5->log;
            v25_message_5->hdr.f0_guaranteedIdx = f10_deliverHeader_1->f0_guaranteedCount;
            v25_message_5->hdr.f4_type = 1; // 1: part success
            v25_message_5->log.f0_numPlayersToSend = f10_deliverHeader_1->f10_numPlayersToSend;
            v25_message_5->log.f4_counter2 = f10_deliverHeader_1->f14_counter2;
            int f18_fullySentData = f10_deliverHeader_1->f18_fullySentData;
            v25_message_5->log.f8_fullySentData = f18_fullySentData;
            v25_message_5->log.fC_statusArr = 0;
            if ( f10_deliverHeader_1->f38_statusList ) {
                int v28_fullySentData = f18_fullySentData;
                if ( MyDeliverHeader::getStatusCount(f10_deliverHeader_1) == f18_fullySentData ) {
                    DeliverStatus *v29_newList = (DeliverStatus *) net::_malloc(sizeof(DeliverStatus) * v28_fullySentData);
                    p_log->fC_statusArr = v29_newList;
                    if ( v29_newList ) {
                        for (DeliverStatusEntry *entry = f10_deliverHeader_1->f38_statusList; entry; ++v29_newList ) {
                            *v29_newList = entry->item;
                            entry = entry->next;
                        }
                    }
                }
            }
            LeaveCriticalSection(&this->dataLock);
            this->messageHandler(this->f226_curPlayer.playersSlot, message_5, 0xC, 5, this->f4_arg);
            EnterCriticalSection(&this->dataLock);
            DeliverStatus *v31_statusArr = p_log->fC_statusArr;
            if ( v31_statusArr ) net::_free(v31_statusArr);
            net::_free(message_5);
        }
    }
    MLDPLAY_SYSTEMQUEUE::release(&f10_deliverHeader_1->f3C_packetsQueue_perPlayer);
    MyDeliverHeader::clearList(f10_deliverHeader_1);
    MLDPLAY_SYSTEMQUEUE::removeEntry(p_f25F_deliverHeadersQueue, deliverHeadersQueue_entry_1);
}
void NetworkServiceProvider::handlePacket_10(MyPacket_10_GuaranteedProgress *packet) {
    if (packet->f0_hdr.f8_messageSize < 0x20u) return;
    if ((unsigned int) packet->f0_hdr.playersSlot >= this->f186_sessionDesc.totalMaxPlayers) return;
    MyPlayerDesc *v4_playerDesc = &this->f24_playerList[packet->f0_hdr.playersSlot];
    if (!v4_playerDesc->isJoined()) return;
    PlayerId f10_playerId = packet->f10_playerId;
    if ( this->f226_curPlayer.playerId != f10_playerId ) {
        this->SendMessage(f10_playerId, packet, 0x2C, 0);
        return;
    }
    if (!(v4_playerDesc->f20_playerId_slot == packet->fC_playerId_slot)) return;
    MLDPLAY_SYSTEMQUEUE_Entry *deliverHeadersQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(&this->f25F_deliverHeadersQueue);
    if ( !deliverHeadersQueue_entry )
        return;
    MyDeliverHeader *f10_deliverHeader;
    while (true) {
        f10_deliverHeader = (MyDeliverHeader *)deliverHeadersQueue_entry->pData;
        deliverHeadersQueue_entry = deliverHeadersQueue_entry->next;
        if ( f10_deliverHeader->f0_guaranteedCount == packet->f14_guaranteedCount ) break;
        if ( !deliverHeadersQueue_entry ) return;
    }
    MLDPLAY_SYSTEMQUEUE_Entry *v8_packetsQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(&f10_deliverHeader->f3C_packetsQueue_perPlayer);
    if ( !v8_packetsQueue_entry ) return;
    MyPacket_D_Guaranteed *v9_guaranteedDeliver;
    while (true) {
        v9_guaranteedDeliver = (MyPacket_D_Guaranteed *)v8_packetsQueue_entry->pData;
        if ( v9_guaranteedDeliver ) {
            if ( v9_guaranteedDeliver->f20_playerId_slot == packet->fC_playerId_slot
                 && v9_guaranteedDeliver->f28_sendScheduled_idx == packet->f18_sendScheduled_idx ) {
                break;
            }
        }
        v8_packetsQueue_entry = v8_packetsQueue_entry->next;
        if ( !v8_packetsQueue_entry )
            return;
    }

    if (v9_guaranteedDeliver->f34_blocksChunk_startIdx == packet->f1C_blocksChunk_startIdx &&
        v9_guaranteedDeliver->f38_transferedPartsCount_max == packet->f20_maxPartsCount) {
        unsigned int v10_receivedIdx = 0;
        char *f3C_partsReceived_arr = v9_guaranteedDeliver->f3C_partsReceived_arr;
        do {
            if ( !f3C_partsReceived_arr[v10_receivedIdx] ) {
                char v12_isRecvd = packet->f24_recvdArr[v10_receivedIdx];
                f3C_partsReceived_arr[v10_receivedIdx] = v12_isRecvd;
                if ( v12_isRecvd )
                    f10_deliverHeader->f20__receivedOffs += 0x1A4;
            }
            ++v10_receivedIdx;
        } while ( v10_receivedIdx < 8 );
        int f34_blocksChunk_startIdx = v9_guaranteedDeliver->f34_blocksChunk_startIdx;
        unsigned int v14_offset = 0;
        if ( f34_blocksChunk_startIdx )
            v14_offset = 0x1A4 * f34_blocksChunk_startIdx - 0x1A4;
        for (unsigned int i = 0; i < 8; ++i ) {
            if ( f3C_partsReceived_arr[i] )
                v14_offset += 0x1A4;
        }
        size_t f2C_totalSize = v9_guaranteedDeliver->f2C_totalSize;
        if ( v14_offset >= f2C_totalSize ) {
            MLDPLAY_SYSTEMQUEUE::removeEntry(&f10_deliverHeader->f3C_packetsQueue_perPlayer, v8_packetsQueue_entry);
            ++f10_deliverHeader->f14_counter2;
        } else {
            unsigned int v17_i = 0;
            unsigned int v18_receivedBlocksCount = 0;
            do {
                if ( f3C_partsReceived_arr[v17_i] )
                    ++v18_receivedBlocksCount;
                ++v17_i;
            } while ( v17_i < 8 );
            if ( v18_receivedBlocksCount >= 8 ) {
                unsigned int v19_sizeLeft = f2C_totalSize - v14_offset;
                v9_guaranteedDeliver->f34_blocksChunk_startIdx = v9_guaranteedDeliver->f38_transferedPartsCount_max + 1;
                if ( v19_sizeLeft > 0x1A4 ) {
                    unsigned int v21_mod = v19_sizeLeft % 0x1A4;
                    unsigned int v22_partsCount = v19_sizeLeft / 0x1A4;
                    if ( v21_mod ) ++v22_partsCount;
                    if ( v22_partsCount <= 8 ) {
                        v9_guaranteedDeliver->f38_transferedPartsCount_max += v22_partsCount;
                    } else {
                        v9_guaranteedDeliver->f38_transferedPartsCount_max += 8;
                    }
                } else {
                    v9_guaranteedDeliver->f38_transferedPartsCount_max += 1;
                }
                memset(v9_guaranteedDeliver->f3C_partsReceived_arr, 0, 8);
            }
        }
    }

    handlePacket_10_handleData();
}

void NetworkServiceProvider::sendScheduledPacketToAllPlayers(ScheduledPacket *a2_scheduledPacket) {
    unsigned int v2_slotId = 0;
    for (unsigned int i = 0; i < 32; ++i, ++v2_slotId) {
        if (((1 << v2_slotId) & a2_scheduledPacket->f8_slotMask) == 0) continue;
        if (v2_slotId >= this->f186_sessionDesc.totalMaxPlayers) continue;

        MyPlayerDesc *v5_playerDesc = &this->f24_playerList[i];
        if (!v5_playerDesc->isJoined()) continue;

        this->SendMessage(
                v5_playerDesc->f20_playerId_slot,
                a2_scheduledPacket->f24_pPacketStart,
                a2_scheduledPacket->f20_packetSize,
                0);
    }
}

int NetworkServiceProvider::hasJoinedPlayer(PlayerId a2_playerId_slot) {
    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
        MyPlayerDesc *f24_curDesc = &this->f24_playerList[i];
        if (!f24_curDesc->isJoined()) continue;
        if (f24_curDesc->f20_playerId_slot != a2_playerId_slot) continue;
        return 1;
    }
    return 0;
}

int NetworkServiceProvider::processDeliverHeaders(
        MLDPLAY_SYSTEMQUEUE *a2_deliverHeadersQueue, DWORD a3_sysTime_ms, DWORD *a4_pSizeLeft) {
    DWORD v32_sleepRequestTime = -1;
    MLDPLAY_SYSTEMQUEUE_Entry *deliverHeadersQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(a2_deliverHeadersQueue);
    while ( deliverHeadersQueue_entry ) {
        int doHandleAndRemove = 0;
        MyDeliverHeader *f10_deliverHeader = (MyDeliverHeader *)deliverHeadersQueue_entry->pData;
        MLDPLAY_SYSTEMQUEUE *p_f3C_packetsQueue_perPlayer = &f10_deliverHeader->f3C_packetsQueue_perPlayer;
        // add item 1000CEC2
        // another get 1000DB89
        for (
                MLDPLAY_SYSTEMQUEUE_Entry *v6_packetsQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(&f10_deliverHeader->f3C_packetsQueue_perPlayer);
                v6_packetsQueue_entry != NULL; v6_packetsQueue_entry = v6_packetsQueue_entry->next) {
            MyPacket_D_Guaranteed *v7_guaranteedDeliver = (MyPacket_D_Guaranteed *)v6_packetsQueue_entry->pData;
            int v8_doCopyNextPacket = 0;
            if ( !this->hasJoinedPlayer(v7_guaranteedDeliver->f20_playerId_slot) ) {
                ++f10_deliverHeader->f18_fullySentData;
                MyDeliverHeader::addStatus(f10_deliverHeader, v7_guaranteedDeliver->f20_playerId_slot, 5);
                if ( (unsigned int)(f10_deliverHeader->f18_fullySentData + f10_deliverHeader->f14_counter2) < f10_deliverHeader->f10_numPlayersToSend ) {
                    MLDPLAY_SYSTEMQUEUE::removeEntry(p_f3C_packetsQueue_perPlayer, v6_packetsQueue_entry);
                    MLDPLAY_SYSTEMQUEUE::getFirst(p_f3C_packetsQueue_perPlayer);
                } else {
                    doHandleAndRemove = 1;
                }
                break;
            }
            if ( v7_guaranteedDeliver->f18_startReadTime ) {
                if ((a3_sysTime_ms - v7_guaranteedDeliver->f14_lastReadTime) >= v7_guaranteedDeliver->f10_deltaTiming) {
                    v7_guaranteedDeliver->f14_lastReadTime = a3_sysTime_ms;
                    v8_doCopyNextPacket = 1;
                }
            } else {
                v7_guaranteedDeliver->f14_lastReadTime = a3_sysTime_ms;
                v7_guaranteedDeliver->f18_startReadTime = a3_sysTime_ms;
                v8_doCopyNextPacket = 1;
            }
            DWORD endTime = v7_guaranteedDeliver->f14_lastReadTime + v7_guaranteedDeliver->f10_deltaTiming;
            DWORD sleepTime = endTime - a3_sysTime_ms;
            if (sleepTime < v32_sleepRequestTime)
                v32_sleepRequestTime = sleepTime;
            if (!v8_doCopyNextPacket) {
                continue;
            }
            DWORD f34_curBlockIdx = v7_guaranteedDeliver->f34_blocksChunk_startIdx;
            int v33_isPartial = 0;
            for (int i = v7_guaranteedDeliver->f34_blocksChunk_startIdx; i <= v7_guaranteedDeliver->f38_transferedPartsCount_max; ++i) {
                char isReceived = v7_guaranteedDeliver->f3C_partsReceived_arr[i];
                DWORD v11_blockOffset = 0x1A4 * i;
                if (isReceived) continue;
                if (*a4_pSizeLeft < 0x1F0u) continue;
                *a4_pSizeLeft -= 0x1F0;
                DWORD f1CSize = f10_deliverHeader->f1C_size;
                char *v13PosSrc = (char *)f10_deliverHeader->f44_fullDataToSend + v11_blockOffset;
                DWORD v14Size;
                if ((f1CSize - v11_blockOffset) < 0x1A4 ) {
                    memcpy(&v7_guaranteedDeliver[1], v13PosSrc, f10_deliverHeader->f1C_size - v11_blockOffset);
                    v14Size = f1CSize - v11_blockOffset + 0x4C;
                    v33_isPartial = 1;
                    v7_guaranteedDeliver->f30_partSize = f10_deliverHeader->f1C_size - v11_blockOffset;
                } else {
                    memcpy(&v7_guaranteedDeliver[1], v13PosSrc, 0x1A4u);
                    v14Size = sizeof(MyPacket_D_Guaranteed) + 0x1A4;  // 0x1F0
                    v7_guaranteedDeliver->f30_partSize = 0x1A4;
                }
                DWORD v15MessageSize = (uint16_t) (v14Size - 0xC);
                DWORD v25Size = v14Size;
                PlayerId v16PlayerIdSlot = v7_guaranteedDeliver->f20_playerId_slot;
                v7_guaranteedDeliver->f0_hdr.f8_messageSize = v15MessageSize;
                v7_guaranteedDeliver->f48_blockIdx = f34_curBlockIdx;
                this->SendMessage(v16PlayerIdSlot, v7_guaranteedDeliver, v25Size, 0);
                if ( v33_isPartial ) break;
            }
        }

        if ( doHandleAndRemove ) {
            if ( (f10_deliverHeader->f8_flags & 1) == 0 ) {
                MyGuarateedData_MsgLog *v17_message_5 = (MyGuarateedData_MsgLog *) net::_malloc(sizeof(MyGuarateedData_MsgLog));
                MyGuarateedData_MsgLog *message_5 = v17_message_5;
                if ( v17_message_5 ) {
                    MyMsgLog *v18_log = &v17_message_5->log;
                    v17_message_5->hdr.f8_pMsgLog = &v17_message_5->log;
                    v17_message_5->hdr.f0_guaranteedIdx = f10_deliverHeader->f0_guaranteedCount;
                    v17_message_5->hdr.f4_type = 3;       // 3: failed
                    v17_message_5->log.f0_numPlayersToSend = f10_deliverHeader->f10_numPlayersToSend;
                    v17_message_5->log.f4_counter2 = f10_deliverHeader->f14_counter2;
                    DWORD f18_fullySentData = f10_deliverHeader->f18_fullySentData;
                    v17_message_5->log.f8_fullySentData = f18_fullySentData;
                    v17_message_5->log.fC_statusArr = NULL;
                    if ( f10_deliverHeader->f38_statusList ) {
                        DWORD v20_fullySentData = f18_fullySentData;
                        if ( MyDeliverHeader::getStatusCount(f10_deliverHeader) == f18_fullySentData ) {
                            DeliverStatus *v21_statusArr = (DeliverStatus *) net::_malloc(sizeof(DeliverStatus) * v20_fullySentData);
                            v18_log->fC_statusArr = v21_statusArr;
                            if ( v21_statusArr ) {
                                for (DeliverStatusEntry *entry = f10_deliverHeader->f38_statusList; entry; ++v21_statusArr ) {
                                    v21_statusArr->playerId_slot = entry->item.playerId_slot;
                                    v21_statusArr->status = entry->item.status;
                                    entry = entry->next;
                                }
                            }
                        }
                    }
                    LeaveCriticalSection(&this->dataLock);
                    this->messageHandler(this->f226_curPlayer.playersSlot, message_5, 0xC, 5, this->f4_arg);
                    EnterCriticalSection(&this->dataLock);
                    DeliverStatus *fC_statusArr = v18_log->fC_statusArr;
                    if ( fC_statusArr )
                        net::_free(fC_statusArr);
                    net::_free(message_5);
                }
            }
            MLDPLAY_SYSTEMQUEUE::release(p_f3C_packetsQueue_perPlayer);
            if ( f10_deliverHeader->f44_fullDataToSend )
                net::_free(f10_deliverHeader->f44_fullDataToSend);
            MyDeliverHeader::clearList(f10_deliverHeader);
            MLDPLAY_SYSTEMQUEUE::removeEntry(a2_deliverHeadersQueue, deliverHeadersQueue_entry);
            deliverHeadersQueue_entry = MLDPLAY_SYSTEMQUEUE::getFirst(a2_deliverHeadersQueue);
        } else {
            deliverHeadersQueue_entry = deliverHeadersQueue_entry->next;
        }
    }
    return v32_sleepRequestTime;
}

void NetworkServiceProvider::releasePacketSendQueue() {
    ScheduledPacket *cur = this->f337_packetSendQueue;
    while ( cur ) {
        ScheduledPacket *toFree = cur;
        cur = cur->f0_next;
        net::_free(toFree);
    }
    this->f337_packetSendQueue = NULL;
}

void NetworkServiceProvider::releaseDeliverQueues() {
    for (MLDPLAY_SYSTEMQUEUE_Entry *curEntry = MLDPLAY_SYSTEMQUEUE::getFirst(&this->f25F_deliverHeadersQueue); curEntry; curEntry = curEntry->next ) {
        MyDeliverHeader *f10_pData = (MyDeliverHeader *)curEntry->pData;
        if ( f10_pData->f44_fullDataToSend ) net::_free(f10_pData->f44_fullDataToSend);
        MyDeliverHeader::clearList(f10_pData);
        MLDPLAY_SYSTEMQUEUE::release(&f10_pData->f3C_packetsQueue_perPlayer);
    }
    MLDPLAY_SYSTEMQUEUE::release(&this->f25F_deliverHeadersQueue);
    MLDPLAY_SYSTEMQUEUE::release(&this->f267_receivedDeliverQueue);
}

int NetworkServiceProvider::AreWeLobbied(MessageHandlerType a2_messageHandler, GUID *a3_guid,
                                         char *a4_outNGLD, DWORD *a5_outPlayers, wchar_t *a6_gameName,
                                         wchar_t *a7_playerName, int a8_totalMaxPlayers, int a9_ignore) {
    // bfnet=100010A0 dplay=10005F50
    if ( !this->Startup(a2_messageHandler) ) return 0;
    if (this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::AreWeLobbied Error:-Already Connected To Session\n");
        return 0;
    }
    memset(this->f5A_ackPacketCount_perPlayerSlot, 0, sizeof(this->f5A_ackPacketCount_perPlayerSlot));
    memset(this->fDA_unused1_perPlayerSlot, 0, sizeof(this->fDA_unused1_perPlayerSlot));
    MyPlayerDesc *f24_playerList = this->f24_playerList;
    this->f15A_ignored_inNewSession = 0;
    this->f15E_nextAckIdx = 0;
    this->f413_AckPacketsCountArr_idx = 0;
    if ( f24_playerList )
        net::_free(f24_playerList);
    MyPlayerDesc *v11_playerList = (MyPlayerDesc *) net::_malloc(sizeof(MyPlayerDesc) * a8_totalMaxPlayers);
    this->f24_playerList = v11_playerList;
    if ( !v11_playerList ) {
        _log("\tNetworkServiceProvider::AreWeLobbied -:couldnot allocate for player list\n");
        return 0x20;
    }
    memset(v11_playerList, 0, sizeof(MyPlayerDesc) * a8_totalMaxPlayers);
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    if ( !this->CreateServiceProvider() ) {
        _log("\tNetworkServiceProvider::AreWeLobbied Error::CouldNot Create Service Provider Thread\n");
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        this->ShutDown();
        return 0;
    }
    if ( !this->startSendDeliverThread() ) {
        _log("\tNetworkServiceProvider::AreWeLobbied Error::CouldNot create System Events\n");
        this->destroyMainThread();
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        this->ShutDown();
        return 0;
    }
    // bfnet=10001240 dplay=100060B0
    int joinStatus = this->BuildSession(
            a2_messageHandler,
            a3_guid,
            a4_outNGLD,
            a5_outPlayers,
            a6_gameName,
            a7_playerName,
            a8_totalMaxPlayers,
            a9_ignore);
    if ( joinStatus != 0x20 ) {
        SetEvent(this->f172_OnPlayerJoined_hEvent);
        if ( this->GetAllPlayersInfo(a5_outPlayers) )
            return joinStatus;
        this->Destroy();
        this->destroySystemThread();
        this->destroyMainThread();
        if ( this->f24_playerList ) {
            net::_free(this->f24_playerList);
            this->f24_playerList = NULL;
        }
        this->ShutDown();
        return 0;
    }
    this->destroySystemThread();
    this->destroyMainThread();
    if ( this->f24_playerList ) {
        net::_free(this->f24_playerList);
        this->f24_playerList = NULL;
    }
    this->ShutDown();
    memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    return 0x20;
}

int NetworkServiceProvider::popReceivedPacketToHandle(PacketHeader *packet) {
    MLDPLAY_SYSTEMQUEUE_Entry *f0_first = this->f257_toHandleList.first;
    if ( !f0_first ) return 0;
    if ( f0_first->_slotPacketCount != this->f15E_nextAckIdx ) return 0;
    this->f15E_nextAckIdx += 1;
    memcpy(packet, f0_first->pData, f0_first->dataSize);
    MLDPLAY_SYSTEMQUEUE_Entry *f4_next = f0_first->next;
    if ( f4_next ) {
        bool v7_bool = f0_first->prev == NULL;
        f4_next->prev = f0_first->prev;
        if ( v7_bool ) {
            this->f257_toHandleList.first = f4_next;
            net::_free(f0_first);
            return 1;
        }
    } else if ( !f0_first->prev ) {
        this->f257_toHandleList.first = NULL;
    }
    net::_free(f0_first);
    return 1;
}

int NetworkServiceProvider::enumAllPlayers(
        GUID *a2_guidInstance, MyPlayerEnumCb a3_callback,
        int a4_ignored, void *a5_arg) {
    int v8_result = 0x20;
    if (!this->f20_isServiceProviderInitialized ) return v8_result;
    if (!this->f226_curPlayer.isConnectedToSession()) return this->EnumPlayers(a2_guidInstance, a3_callback, a4_ignored, a5_arg);
    if (!a3_callback) return v8_result;

    EnterCriticalSection(&this->dataLock);
    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
        MyPlayerDesc *f24_curDesc = &this->f24_playerList[i];
        if (!f24_curDesc->isJoined()) continue;
        MyPlayerCbData v9_playerData;
        v9_playerData.f0_flags = v9_playerData.f0_flags & 0xF0 | 1;
        v9_playerData.f0_flags = f24_curDesc->flags ^ (f24_curDesc->flags ^ v9_playerData.f0_flags) & 0xF;
        v9_playerData.field_1 = f24_curDesc->field_24;
        v9_playerData.f26_playerId_slot = f24_curDesc->f20_playerId_slot;
        wcscpy(v9_playerData.f6_shortName, f24_curDesc->f0_playername);
        LeaveCriticalSection(&this->dataLock);
        a3_callback(&v9_playerData, (int)a5_arg);
        EnterCriticalSection(&this->dataLock);
    }
    LeaveCriticalSection(&this->dataLock);
    return 2;
}

int NetworkServiceProvider::SendData(
        unsigned int a2_playerListIdx_m1_m2, const void *a3_data, size_t Size, int a5_flags,
        unsigned int *a6_outGuaranteedCount) {
    if ( (a5_flags & 2) != 0 ) {
        return this->SendDataGuaranteed(
                a2_playerListIdx_m1_m2,
                a3_data,
                Size,
                a5_flags,
                a6_outGuaranteedCount);
    }
    return this->SendDataDatagram(
            a2_playerListIdx_m1_m2,
            a3_data,
            Size,
            a5_flags,
            a6_outGuaranteedCount);
}

int NetworkServiceProvider::SendDataGuaranteed(
        unsigned int a2_playerListIdx_m1_m2, const void *a3_data, size_t Size,
        int a5_flags, unsigned int *a6_outGuaranteedCount) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tNetworkServiceProvider::SendDataGuaranteed Error:Not Initialised\n");
        return 0x20;
    }
    if (!Size) {
        _log("\tNetworkServiceProvider::SendDataGuaranteed Error:Size is 0\n");
        return 0x20;
    }
    if (!this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::SendDataGuaranteed Error:Not Connected To Session\n");
        return 0x20;
    }
    int v7_result = 0x20;
    EnterCriticalSection(&this->dataLock);
    if (this->AddGuaranteedPacketToMessageQueue(
            a2_playerListIdx_m1_m2,
            a3_data,
            Size,
            a6_outGuaranteedCount)) {
        v7_result = 2;
    }
    LeaveCriticalSection(&this->dataLock);
    return v7_result;
}

int NetworkServiceProvider::SendDataDatagram(
        int a2_playerListIdx_m1_m2, const void *a3_data, size_t a4_size, int a5_flags,
        unsigned int *a6_outGuaranteedCount) {
    PlayerId f20_playerId_slot = {0};
    int v16_doHandle = 0;
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tNetworkServiceProvider::SendDataDatagram Error:Not Initialised\n");
        return 0x20;
    }
    if ( !a4_size ) return 0x20;
    unsigned int v7_size = a4_size;
    if (!this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::SendDataDatagram Error:Not Connected To Session\n");
        return 0x20;
    }
    a4_size += sizeof(PacketHeader);
    MyPacket_3_Data *v8_packetbuf = (MyPacket_3_Data *) net::operator_new(a4_size);
    if ( !v8_packetbuf ) return 0x20;

    int v15_result = 0x20;
    EnterCriticalSection(&this->dataLock);
    if ( a2_playerListIdx_m1_m2 == net_AllPlayers || a2_playerListIdx_m1_m2 == net_HostPlayer ) {
        f20_playerId_slot.value = a2_playerListIdx_m1_m2;
        v16_doHandle = 1;
    } else if ( a2_playerListIdx_m1_m2 < this->f186_sessionDesc.totalMaxPlayers ) {
        MyPlayerDesc *v10_playerDesc = &this->f24_playerList[a2_playerListIdx_m1_m2];
        if (v10_playerDesc->isJoined()) {
            f20_playerId_slot = v10_playerDesc->f20_playerId_slot;
            v16_doHandle = 1;
        } else {
            v15_result = 0x40;
        }
    } else {
        v15_result = 0x40;
    }
    LeaveCriticalSection(&this->dataLock);

    if (!v16_doHandle ) {
        net::operator_delete(v8_packetbuf);
        return v15_result;
    }
    v8_packetbuf->f0_hdr.signature = PacketHeader::MAGIC;
    uint16_t f8_playersSlot = this->f226_curPlayer.playersSlot;
    v8_packetbuf->f0_hdr.f8_messageSize = (uint16_t) v7_size;
    v8_packetbuf->f0_hdr.playerListIdx_m1_m2 = a2_playerListIdx_m1_m2;
    const void *v12_data = a3_data;
    v8_packetbuf->f0_hdr.playersSlot = f8_playersSlot;
    v8_packetbuf->f0_hdr.packetTy = MyPacket_3_Data::ID;
    v8_packetbuf->f0_hdr.f2 = 0;
    int v13_isLocalPacket = 0;
    memcpy(&v8_packetbuf[1], v12_data, v7_size);
    if (this->f226_curPlayer.isHost() && (
            v8_packetbuf->f0_hdr.playerListIdx_m1_m2 == net_AllPlayers ||
            v8_packetbuf->f0_hdr.playerListIdx_m1_m2 == net_HostPlayer
    ) ) {
        int size;
        this->_handleMessage((PacketHeader *) v8_packetbuf, 4u, &size);
        v13_isLocalPacket = 1;
    }
    if ( !v13_isLocalPacket ) {
        EnterCriticalSection(&this->dataLock);
        this->SendMessage(f20_playerId_slot, v8_packetbuf, a4_size, 0);
        LeaveCriticalSection(&this->dataLock);
    }
    net::operator_delete(v8_packetbuf);
    return 2;
}

int NetworkServiceProvider::SendChat(unsigned int a2_FFFF, wchar_t *chatMesage, int a4_ignored1, unsigned int *a5_ignored2) {
    int v20_doSendMessage = 0;
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tNetworkServiceProvider::SendChat Error:Not Initialised\n");
        return 0x20;
    }
    size_t v6_strLen = wcslen(chatMesage);
    int v7_strSize = 2 * v6_strLen + 2;
    size_t v8_dataSize = 2 * v6_strLen + 0xE;
    int v22_dataSize = v8_dataSize;
    if ( !v8_dataSize ) return 0x20;
    if (!this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::SendChat Error:Not Initialised\n");
        return 0x20;
    }
    MyPacket_4_ChatMessage *v9_data = (MyPacket_4_ChatMessage *) net::operator_new(v8_dataSize);
    if ( !v9_data ) return 0x20;

    int v19_status = 0x20;
    EnterCriticalSection(&this->dataLock);
    PlayerId f20_playerId_slot = {0};
    if ( a2_FFFF == net_AllPlayers || a2_FFFF == net_HostPlayer ) {
        f20_playerId_slot.value = a2_FFFF;
        v20_doSendMessage = 1;
    } else if ( a2_FFFF < this->f186_sessionDesc.totalMaxPlayers ) {
        if (this->f24_playerList[a2_FFFF].isJoined()) {
            f20_playerId_slot = this->f24_playerList[a2_FFFF].f20_playerId_slot;
            v20_doSendMessage = 1;
        } else {
            v19_status = 0x40;
        }
    } else {
        v19_status = 0x40;
    }
    LeaveCriticalSection(&this->dataLock);

    if (!v20_doSendMessage ) {
        net::operator_delete(v9_data);
        return v19_status;
    }

    v9_data->f0_hdr.signature = PacketHeader::MAGIC;
    v9_data->f0_hdr.playersSlot = this->f226_curPlayer.playersSlot;
    v9_data->f0_hdr.playerListIdx_m1_m2 = a2_FFFF;
    v9_data->f0_hdr.packetTy = MyPacket_4_ChatMessage::ID;
    v9_data->f0_hdr.f8_messageSize = v7_strSize;
    v9_data->f0_hdr.f2 = 0;
    memcpy(&v9_data->fC_message, chatMesage, v7_strSize);
    int v17_isHandled = 0;
    if ( this->f226_curPlayer.isHost() && (
            v9_data->f0_hdr.playerListIdx_m1_m2 == net_AllPlayers ||
            v9_data->f0_hdr.playerListIdx_m1_m2 == net_HostPlayer
    ) ) {
        int size;
        this->_handleMessage((PacketHeader *) v9_data, 6u, &size);
        v17_isHandled = 1;
    }
    if ( !v17_isHandled ) {
        EnterCriticalSection(&this->dataLock);
        this->SendMessage(f20_playerId_slot, v9_data, v22_dataSize, 0);
        LeaveCriticalSection(&this->dataLock);
    }

    net::operator_delete(v9_data);
    return 2;
}

int NetworkServiceProvider::AddGuaranteedPacketToMessageQueue(
        unsigned int a2_playerListIdx_m1_m2, const void *a3_data,
        size_t a4_dataSize, unsigned int *a5_outGuaranteedIdx) {
    int v5_hasAnyoneToSend = 0;
    PlayerId v29_playerId_slot = {0};
    int f2C_packet_D_Guaranteed_sendScheduled_count = 0;
    unsigned int v30_playerListIdx_m1_m2_1 = a2_playerListIdx_m1_m2;
    int v27_numPlayersToSend = 0;
    int v32_return = 0;
    patch::log::gdata("queue dty=%X sz=%X pid=%08X",
                      (int) (*(uint8_t *) a3_data), a4_dataSize, a2_playerListIdx_m1_m2);
    if ( a2_playerListIdx_m1_m2 == net_HostPlayer ) {
        MyPlayerDesc *f24_desc = this->f24_playerList;
        MyPlayerDesc *v8_listEnd = &f24_desc[this->f186_sessionDesc.totalMaxPlayers];
        if ( f24_desc < v8_listEnd ) {
            while (true) {
                if ( f24_desc->isJoined() && f24_desc->isHost() ) {
                    PlayerId f20_playerId_slot = f24_desc->f20_playerId_slot;
                    f2C_packet_D_Guaranteed_sendScheduled_count = f24_desc->f2C_packet_D_Guaranteed_sendScheduled_count;
                    f24_desc->f2C_packet_D_Guaranteed_sendScheduled_count = f2C_packet_D_Guaranteed_sendScheduled_count + 1;
                    v29_playerId_slot = f20_playerId_slot;
                    a2_playerListIdx_m1_m2 = f24_desc->f35_slotNo;
                    v5_hasAnyoneToSend = 1;
                    // if(host player is current player) return 0;
                    if ( f20_playerId_slot == this->f226_curPlayer.playerId )
                        return 0;
                    v27_numPlayersToSend = 1;
                    break;
                }
                if ( ++f24_desc >= v8_listEnd )
                    break;
            }
        }
    } else if ( a2_playerListIdx_m1_m2 == net_AllPlayers ) {
        unsigned int f24_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
        if ( f24_totalMaxPlayers > 1 ) {
            MyPlayerDesc *v13_desc = this->f24_playerList;
            v27_numPlayersToSend = 0;
            for (MyPlayerDesc *i = &v13_desc[f24_totalMaxPlayers]; v13_desc < i; ++v13_desc ) {
                // player is joined && player is not sender
                if ( v13_desc->isJoined() && v13_desc->f20_playerId_slot != this->f226_curPlayer.playerId ) {
                    v5_hasAnyoneToSend = 1;
                    ++v27_numPlayersToSend;
                }
            }
        }
    } else {
        v27_numPlayersToSend = 1;
        if ( a2_playerListIdx_m1_m2 < this->f186_sessionDesc.totalMaxPlayers ) {
            MyPlayerDesc *v15_playerDesc = &this->f24_playerList[a2_playerListIdx_m1_m2];
            if (v15_playerDesc->isJoined()) {
                v5_hasAnyoneToSend = 1;
                v29_playerId_slot = v15_playerDesc->f20_playerId_slot;
                f2C_packet_D_Guaranteed_sendScheduled_count = v15_playerDesc->f2C_packet_D_Guaranteed_sendScheduled_count;
                v15_playerDesc->f2C_packet_D_Guaranteed_sendScheduled_count = f2C_packet_D_Guaranteed_sendScheduled_count + 1;
            }
        }
    }
    if ( !v5_hasAnyoneToSend ) {
        return v32_return;
    }
    MyPacket_D_Guaranteed *v16_packetBuf = (MyPacket_D_Guaranteed *) net::_malloc(sizeof(MyPacket_D_Guaranteed) + 0x1A4);
    if ( !v16_packetBuf ) {
        _log("NetworkServiceProvider::AddGuaranteedPacketToMessageQueue Error:-Couldnot allocate Temporary Buffer\n");
        return 0;
    }
    void *v17_dataBuf = net::_malloc(a4_dataSize);
    MyDeliverHeader v33_deliverHeader;
    v33_deliverHeader.f44_fullDataToSend = v17_dataBuf;
    if ( !v17_dataBuf ) {
        _log("NetworkServiceProvider::AddGuaranteedPacketToMessageQueue Error:- Couldnot allocate memory buffer\n");
        net::_free(v16_packetBuf);
        return 0;
    }
    memcpy(v17_dataBuf, a3_data, a4_dataSize);
    unsigned int fC_guaranteedScheduledIdx = this->f226_curPlayer.guaranteedScheduledCount;
    v33_deliverHeader.f0_guaranteedCount = fC_guaranteedScheduledIdx;
    v33_deliverHeader.f4_playerListIdx_m1_m2 = v30_playerListIdx_m1_m2_1;
    this->f226_curPlayer.guaranteedScheduledCount = fC_guaranteedScheduledIdx + 1;
    if ( a5_outGuaranteedIdx ) {
        v33_deliverHeader.f8_flags = 0;
        *a5_outGuaranteedIdx = fC_guaranteedScheduledIdx;
    } else {
        v33_deliverHeader.f8_flags = 1;
    }
    v33_deliverHeader.fC_sendScheduled_idx = f2C_packet_D_Guaranteed_sendScheduled_count;
    v33_deliverHeader.f10_numPlayersToSend = v27_numPlayersToSend;
    v33_deliverHeader.f14_counter2 = 0;
    v33_deliverHeader.f18_fullySentData = 0;
    v33_deliverHeader.f1C_size = a4_dataSize;
    memset(&v33_deliverHeader.f20__receivedOffs, 0, 0x24);
    MLDPLAY_SYSTEMQUEUE_Entry *v20_deliverHeader_entry = MLDPLAY_SYSTEMQUEUE::addEntry(
            &this->f25F_deliverHeadersQueue,
            &v33_deliverHeader,
            0x48u,
            0x48);
    if ( !v20_deliverHeader_entry ) {
        net::_free(v16_packetBuf);
        net::_free(v33_deliverHeader.f44_fullDataToSend);
        _log("NetworkServiceProvider::AddGuaranteedPacketToMessageQueue Error:- Couldnot add deliver_header to memory queue\n");
        return 0;
    }
    MyDeliverHeader *a5_deliverHeader = (MyDeliverHeader *)v20_deliverHeader_entry->pData;
    int a3_packetAdded = 0;
    MyPlayerDesc *v21_desc = this->f24_playerList;
    unsigned int v30_playerListIdx_m1_m2 = a2_playerListIdx_m1_m2;
    MyPlayerDesc *v1_desc = v21_desc;
    if ( v21_desc < &v21_desc[this->f186_sessionDesc.totalMaxPlayers] ) {
        do {
            int v22_doAddPacket = 0;
            if ( v30_playerListIdx_m1_m2 == net_AllPlayers ) {  // all players
                // player is joined && player is not sender
                if (v21_desc->isJoined() && v21_desc->f20_playerId_slot != this->f226_curPlayer.playerId ) {
                    if(v21_desc->f35_slotNo) {
                        v22_doAddPacket = 1;
                    }
                    v29_playerId_slot = v21_desc->f20_playerId_slot;
                    a2_playerListIdx_m1_m2 = (uint16_t) v21_desc->f35_slotNo;
                    f2C_packet_D_Guaranteed_sendScheduled_count = v21_desc->f2C_packet_D_Guaranteed_sendScheduled_count;
                    v21_desc->f2C_packet_D_Guaranteed_sendScheduled_count = f2C_packet_D_Guaranteed_sendScheduled_count + 1;
                    v22_doAddPacket = 1;
                }
                v1_desc = ++v21_desc;
            } else {
                v22_doAddPacket = 1;
            }
            if ( v22_doAddPacket ) {
                PlayerId f4_playerId = this->f226_curPlayer.playerId;
                v16_packetBuf->f20_playerId_slot = v29_playerId_slot;
                v16_packetBuf->f1C_playerId = f4_playerId;
                v16_packetBuf->f2C_totalSize = a4_dataSize;
                memset(v16_packetBuf->f3C_partsReceived_arr, 0, 8);
                v16_packetBuf->f34_blocksChunk_startIdx = 0;
                v16_packetBuf->fC__timeout = 60000;
                v16_packetBuf->f10_deltaTiming = 500;
                v16_packetBuf->f18_startReadTime = 0;
                v16_packetBuf->f14_lastReadTime = 0;
                v16_packetBuf->f28_sendScheduled_idx = f2C_packet_D_Guaranteed_sendScheduled_count;
                if ( a4_dataSize > 0x1A4 ) {
                    v16_packetBuf->f30_partSize = 0x1A4;
                    v16_packetBuf->f44_totalPartsCount = a4_dataSize / 0x1A4;
                    if ( a4_dataSize % 0x1A4 )
                        v16_packetBuf->f44_totalPartsCount = a4_dataSize / 0x1A4 + 1;
                    size_t f44_totalPartsCount = v16_packetBuf->f44_totalPartsCount;
                    if ( f44_totalPartsCount <= 8 )
                        v16_packetBuf->f38_transferedPartsCount_max = f44_totalPartsCount - 1;
                    else
                        v16_packetBuf->f38_transferedPartsCount_max = 7;
                    v21_desc = v1_desc;
                } else {
                    v16_packetBuf->f30_partSize = a4_dataSize;
                    v16_packetBuf->f44_totalPartsCount = 1;
                    v16_packetBuf->f38_transferedPartsCount_max = 0;
                }
                v16_packetBuf->f48_blockIdx = 0;
                v16_packetBuf->f28_sendScheduled_idx = f2C_packet_D_Guaranteed_sendScheduled_count;
                v16_packetBuf->f24_guaranteedCount = v33_deliverHeader.f0_guaranteedCount;
                v16_packetBuf->f0_hdr.signature = PacketHeader::MAGIC;
                v16_packetBuf->f0_hdr.playerListIdx_m1_m2 = a2_playerListIdx_m1_m2;
                v16_packetBuf->f0_hdr.playersSlot = this->f226_curPlayer.playersSlot;
                v16_packetBuf->f0_hdr.f2 = 0;
                v16_packetBuf->f0_hdr.packetTy = MyPacket_D_Guaranteed::ID;
                MLDPLAY_SYSTEMQUEUE::addEntry(&a5_deliverHeader->f3C_packetsQueue_perPlayer, v16_packetBuf, sizeof(MyPacket_D_Guaranteed) + 0x1A4, sizeof(MyPacket_D_Guaranteed) + 0x1A4);  // 0x1F0
                a3_packetAdded = 1;
            }
        } while ( v30_playerListIdx_m1_m2 == net_AllPlayers && v21_desc < &this->f24_playerList[this->f186_sessionDesc.totalMaxPlayers] );
    }
    if ( a3_packetAdded ) {
        SetEvent(this->f17a_OnPacket_D_Guaranteed_added_hEvent);
        v32_return = 2;
    }
    net::_free(v16_packetBuf);
    return v32_return;
}



