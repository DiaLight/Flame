//
// Created by DiaLight on 19.12.2024.
//

#include "MLDPlay.h"
#include "BullfrogNET.h"
#include "DPlay.h"
#include "logging.h"
#include "globals.h"
#include "weanetr_memory.h"

using namespace net;

int MLDPlay::StartupNetwork(MessageHandlerType messageHandler) {
    if ( !messageHandler ) return 1;
    this->f8_messageHandler = messageHandler;
    this->fc_hasHandler = 1;
    // call _log
    return 1;
}

int MLDPlay::ShutdownNetwork() {
    if ( !this->fc_hasHandler ) return 0;

    this->f8_messageHandler = 0;
    this->fc_hasHandler = 0;

    MyLocalService *service = this->f0_service_first;
    while (service != NULL) {
        MyLocalService *toFree = service;
        service = service->f1C_next;
        net::_free(toFree);
    }
    this->f0_service_first = NULL;

    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (provider) {
        provider->ShutDown();
        net::operator_delete(provider);
        // call _log
        this->f4_pNetworkServiceProvider = NULL;
        // call _log
    }
    return 0;
}

int MLDPlay::SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) {
    if ( !a2_dplayAddr ) return 0;
    if ( a2_dplayAddr->f0_signature[0] == 'B' && a2_dplayAddr->f0_signature[1] == 'F' ) {
        if ( a2_dplayAddr->f2_guid_BFSPGUID_TCPIP == BFSPGUID_TCPIP) {
            this->f4_pNetworkServiceProvider = new BullfrogNET();
        }
    } else {
        this->f4_pNetworkServiceProvider = net::call_new<DPlay>();
    }

    NetworkServiceProvider *v4_provider = this->f4_pNetworkServiceProvider;
    if (!v4_provider) return 0;
    if (!v4_provider->Startup(this->f8_messageHandler)) return 0;
    if (!v4_provider->SetupConnection(a2_dplayAddr, a3_guid, a4_arg)) return 0;
    return 1;
}

int MLDPlay::EnumerateServices(EnumerateServicesCallback a2_callback, void *a3_arg) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::EnumerateServices Error: Not Initialised\n");
        return 0;
    }
    if (!this->f0_service_first) {
        if (NetworkServiceProvider *prov = net::call_new<BullfrogNET>()) {
            // bfnet=10001A90 dplay=100067D0
            prov->EnumerateLocalServices([](
                    MyLocalService *a1_service, wchar_t *name,
                    GUID *a3_guid, DWORD a4_idx, void *arg
            ) { ((MLDPlay *) arg)->serviceCallback(a1_service, name, a3_guid, a4_idx); }, this);
            net::call_delete<NetworkServiceProvider>(prov);
        }
        if (NetworkServiceProvider *prov = net::call_new<DPlay>()) {
            prov->EnumerateLocalServices([](
                    MyLocalService *a1_service, wchar_t *name,
                    GUID *a3_guid, DWORD a4_idx, void *arg
            ) { ((MLDPlay *) arg)->serviceCallback(a1_service, name, a3_guid, a4_idx); }, this);
            net::call_delete<NetworkServiceProvider>(prov);
        }
        // this->f0_service_first has changed
    }
    MyLocalService *curService = this->f0_service_first;
    if (!this->f0_service_first) return 0;
    do {
        a2_callback(
                curService,
                curService->f18_pName,
                curService->f24_pGuid,
                curService->f10_count,
                a3_arg);
        curService = curService->f1C_next;
    } while (curService);
    return 1;
}

void MLDPlay::serviceCallback(MyLocalService *a1_service, wchar_t *name, GUID *a3_guid, unsigned int a4_idx) {
    if (!a1_service) return;
    MyLocalService *v9_newService = (MyLocalService *)net::_malloc(
            sizeof(MyLocalService) +
            (wcslen(name) + 1) * sizeof(wchar_t) +
            a1_service->f14_addr_size + a1_service->f10_count * sizeof(GUID)
    );
    if ( this->f0_service_first ) {
        MyLocalService *lastEntry;
        MyLocalService *curService = this->f0_service_first;
        do {
            lastEntry = curService;
            curService = curService->f1C_next;
        } while ( curService );
        lastEntry->f1C_next = v9_newService;
    } else {
        this->f0_service_first = v9_newService;
    }
    if (!v9_newService) return;
    memset(v9_newService, 0, sizeof(MyLocalService));
    v9_newService->f0_guid = a1_service->f0_guid;
    v9_newService->f10_count = a1_service->f10_count;
    v9_newService->f14_addr_size = a1_service->f14_addr_size;
    v9_newService->f18_pName = v9_newService->f28_name;
    v9_newService->f1C_next = NULL;

    uint8_t *dataPos = (uint8_t *) v9_newService->f28_name;

    wcscpy((wchar_t *) dataPos, a1_service->f18_pName);
    dataPos += (wcslen(v9_newService->f28_name) + 1) * sizeof(wchar_t);

    v9_newService->f20_addr = (MyLocalServiceAddr *) dataPos;
    memcpy(dataPos, a1_service->f20_addr, a1_service->f14_addr_size);
    dataPos += a1_service->f14_addr_size;

    v9_newService->f24_pGuid = (GUID *) dataPos;
    memcpy(dataPos, a1_service->f24_pGuid, a1_service->f10_count * sizeof(GUID));
}

int MLDPlay::AreWeLobbied(MessageHandlerType messageHandler, GUID *a3_guid, char *a4_outNGLD,
                          DWORD *a5_outPlayers, wchar_t *a6_gameName, wchar_t *a7_playerName,
                          unsigned int a8_totalMaxPlayers, unsigned int a9_ignore) {
    int v10_result = 0x20;
    if (!this->fc_hasHandler && !(this->StartupNetwork(messageHandler), this->fc_hasHandler)) {
        _log("MLDPlay::AreWeLobbied Error:-Not Initialised\n");
        if (v10_result == 0x20)
            this->ShutdownNetwork();
        return v10_result;
    }
    int v16_isLobbied = 0;
    NetworkServiceProvider *v12_provider = net::call_new<DPlay>();
    this->f4_pNetworkServiceProvider = v12_provider;
    if (v12_provider) {
        v10_result = v12_provider->AreWeLobbied(
                messageHandler,
                a3_guid,
                a4_outNGLD,
                a5_outPlayers,
                a6_gameName,
                a7_playerName,
                a8_totalMaxPlayers,
                a9_ignore);
        if (v10_result != 0x20)
            v16_isLobbied = 1;
    } else {
        _log("MLDPlay::AreWeLobbied Error:-Couldnot allocate DPlay Class\n");
    }
    if (!v16_isLobbied) {
        if (v12_provider) {
            net::operator_delete(v12_provider);
            this->f4_pNetworkServiceProvider = NULL;
        }
        BullfrogNET *bfnet = net::call_new<BullfrogNET>();
        this->f4_pNetworkServiceProvider = bfnet;
        v12_provider = bfnet;
        if (bfnet) {
            v10_result = bfnet->AreWeLobbied(
                    messageHandler,
                    a3_guid,
                    a4_outNGLD,
                    a5_outPlayers,
                    a6_gameName,
                    a7_playerName,
                    a8_totalMaxPlayers,
                    a9_ignore);
            if (v10_result != 0x20)
                v16_isLobbied = 1;
        }
    }
    if (!v16_isLobbied && v12_provider) {
        net::operator_delete(v12_provider);
        this->f4_pNetworkServiceProvider = NULL;
    }
    if (v10_result == 0x20)
        this->ShutdownNetwork();
    return v10_result;
}

int MLDPlay::EnumerateLobbyApplications(
        MessageHandlerType a2_messageHandler, EnumerateSessionsCallback a3_ignore, void *a4_ignore) {
    NetworkServiceProvider *v6_provider = net::call_new<DPlay>();
    if ( !v6_provider ) return 0;
    int result = v6_provider->enumLocalApplications(0, 0);
    net::operator_delete(v6_provider);
    return result;
}

int MLDPlay::RunLobbyApplication(
        int a2_flags, wchar_t *a3_sessionName, wchar_t *a4_playerName, GUID *a5_guidApplication,
        wchar_t *a6_address, unsigned int a7_ignore, unsigned int a8_maxPlayers) {
    NetworkServiceProvider *v10_provider = net::call_new<DPlay>();
    if ( !v10_provider ) return 0x20;
    int v8_result = v10_provider->connectLobby(
            a2_flags, a3_sessionName, a4_playerName,
            a5_guidApplication, a6_address, a7_ignore, a8_maxPlayers);
    net::operator_delete(v10_provider);
    return v8_result;
}

BOOL MLDPlay::IsProviderInitialised() {
    if (!this->fc_hasHandler) return false;
    if (!this->f4_pNetworkServiceProvider) return false;
    return this->f4_pNetworkServiceProvider->f20_isServiceProviderInitialized != 0;
}

int MLDPlay::CreateSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
                           MySessionCredentials *a5_cred, unsigned int a6_flags) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::CreateSession Error:-MLDPlay Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::CreateSession Error:-No Service Provider has been setup (hint:SetupConnection)\n");
        return 0x20;
    }
    int result = provider->CreateSession(
            a2_outPlayers,
            a3_gameName,
            a4_playerName,
            a5_cred,
            a6_flags);
    if (result != 2 && result != 1) {
        _log("MLDPlay::CreateSession Error:- Failed Error code 0x%x\n", result);
    }
    return result;
}

int MLDPlay::JoinSession(struct MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName,
                         MySessionCredentials *a5_cred) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::JoinSession Error:-MLDPlay Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::JoinSession Error:-No Service Provider has been setup (hint:SetupConnection)\n");
        return 0x20;
    }
    int result = provider->JoinSession(
            a2_desc,
            a3_outPlayerCount,
            a4_playerName,
            a5_cred);
    if (result != 2 && result != 1) {
        _log("MLDPlay::JoinSession Error:- Failed Error code 0x%x\n", result);
    }
    return result;
}

int MLDPlay::DestroySession() {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::DestroySession Error:-MLDPlay Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::DestroySession Error:-No Service Provider has been setup (hint:SetupConnection)\n");
        return 0x20;
    }
    _log("MLDPlay::DestroySession\n");
    provider->Destroy();
    return 0x20;
}

int MLDPlay::EnumerateSessions(unsigned int a2_zero, EnumerateSessionsCallback a3_callback, unsigned int a4_flags,
                               void *a5_arg) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::EnumerateSessions Error:-Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::EnumerateSessions Error:-No Service Provider setup.\n");
        return 0x20;
    }
    return provider->EnumerateSessions(
            a2_zero,
            a3_callback,
            a4_flags,
            a5_arg);
}

int MLDPlay::EnumeratePlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, unsigned int a4_ignored, void *a5_arg) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::EnumeratePlayers Error:-Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::EnumeratePlayers Error:-No Service Provider setup.\n");
        return 0x20;
    }
    return provider->enumAllPlayers(
            a2_guidInstance,
            a3_callback,
            a4_ignored,
            a5_arg);
}

int MLDPlay::SendData(unsigned int a2_playerListIdx_m1_m2, void *a3_data, size_t Size, unsigned int a5_flags,
                      unsigned int *a6_outGuaranteedCount) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::SendData Error:-MLDPlay Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::SendData Error:-No Service Provider has been setup (hint:SetupConnection)\n");
        return 0x20;
    }
    return provider->SendData(
            a2_playerListIdx_m1_m2,
            a3_data,
            Size,
            a5_flags,
            a6_outGuaranteedCount);
}

int MLDPlay::SendChat(unsigned int a2_FFFF, wchar_t *chatMessage, unsigned int a4_ignored1, unsigned int *a5_ignored2) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::SendChat Error:-MLDPlay Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::SendChat Error:-No Service Provider has been setup (hint:SetupConnection)\n");
        return 0x20;
    }
    return provider->SendChat(a2_FFFF, chatMessage, a4_ignored1, a5_ignored2);
}

int MLDPlay::GetSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) {
    if ( !this->fc_hasHandler ) return 0x20;
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) return 0x20;
    return provider->getSessionDesc(a2_pDesc, a3_pSize);
}

int MLDPlay::SetSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, unsigned int a3_size) {
    if ( !this->fc_hasHandler ) return 0x20;
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) return 0x20;
    return provider->setSessionDesc(a2_desc, a3_size);
}

int MLDPlay::SendMSResults(char *a2_message) {
    if ( !this->fc_hasHandler ) return 0x20;
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) return 0x20;
    return provider->SendMSResults(a2_message);
}

DWORD MLDPlay::GetCurrentMs() {
    struct mmtime_tag pmmt;
    pmmt.wType = 1;
    timeGetSystemTime(&pmmt, 0xCu);
    return pmmt.u.ms;
}

void MLDPlay::EnableNewPlayers(int a2_enabled) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::EnableNewPlayers Error:-Not Initialised\n");
        return;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::EnableNewPlayers Error:-No Service Provider\n");
        return;
    }
    provider->EnableNewPlayers(a2_enabled);
}

int MLDPlay::DumpPlayer(unsigned int a2_slot) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::DestroyPlayer Error:-Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::DestroyPlayer Error:-No Service Provider\n");
        return 0x20;
    }
    return provider->DestroySession(a2_slot);  // is this is devs mistake?
}

int MLDPlay::GetPlayerDesc(MLDPLAY_PLAYERINFO *playerDesc, unsigned int a3_slot_m2_m3) {
    if ( !playerDesc ) {
        _log("MLDPlay::GetPlayerDesc Error:-Parameter (MLDPLAY_PLAYERINFO) passed must be NON NULL.\n");
        return 0x20;
    }
    if ( !this->fc_hasHandler ) {
        _log("MLDPlay::GetPlayerDesc Error:-Not Initialised.\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if ( !provider ) {
        _log("MLDPlay::GetPlayerDesc Error:-No Service Provider.\n");
        return 0x20;
    }
    if (!provider->f226_curPlayer.isConnectedToSession())
        return 0x20;
    int countLeft = 2000;
    MSG Msg;
    while ( PeekMessageA(&Msg, NULL, 0, 0, 0) ) {
        if ( countLeft-- == 0 ) break;
        if ( !GetMessageA(&Msg, NULL, 0, 0) ) break;
        TranslateMessage(&Msg);
        DispatchMessageA(&Msg);
    }
    EnterCriticalSection(&provider->dataLock);
    MyPlayerDesc *f24_playerList = provider->f24_playerList;
    if ( !f24_playerList ) {
        LeaveCriticalSection(&provider->dataLock);
        return 0x20;
    }
    unsigned int f8_playersSlot = a3_slot_m2_m3;
    if ( a3_slot_m2_m3 == net_CurrentPlayer ) {
        f8_playersSlot = provider->f226_curPlayer.playersSlot;
    } else if (a3_slot_m2_m3 == net_HostPlayer) {
        for (int i = 0; i < provider->f186_sessionDesc.totalMaxPlayers; ++i) {
            MyPlayerDesc *desc = &provider->f24_playerList[i];
            if (!desc->isJoined()) continue;
            if (!desc->isHost()) continue;
            f8_playersSlot = desc->f35_slotNo;
            break;
        }
        if (f8_playersSlot == net_HostPlayer) {
            _log("Mldplay::GetPlayerDesc:-Internal Error No Host found\n");
            LeaveCriticalSection(&provider->dataLock);
            return 0x20;
        }
    }
    int result = 0x20;
    if (f8_playersSlot < provider->f186_sessionDesc.totalMaxPlayers ) {
        MyPlayerDesc *v8_playerDesc = &f24_playerList[f8_playersSlot];
        if (v8_playerDesc->isJoined()) {
            playerDesc->f0_flags = v8_playerDesc->flags & 0xF0 | 1;
            playerDesc->f26_playerId_slot = v8_playerDesc->f20_playerId_slot;
            playerDesc->f5_slotNo = v8_playerDesc->f35_slotNo;
            playerDesc->dword_1 = v8_playerDesc->field_24;
            wcscpy(playerDesc->f6_shortName, f24_playerList[f8_playersSlot].f0_playername);
            result = 2;
        }
    }
    LeaveCriticalSection(&provider->dataLock);
    return result;
}

unsigned int MLDPlay::GetPlayerAddress(unsigned int a2_slot_m2_m3, MyPlayerSubDesc *a3_pAddr, unsigned int *a4_pSize) {
    if ( !this->fc_hasHandler ) {
        _log("MLDPlay::GetPlayerAddress Error:-Not Initialised.\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if ( !provider ) {
        _log("MLDPlay::GetPlayerAddress Error:-No Service Provider.\n");
        return 0x20;
    }
    if (!provider->f226_curPlayer.isConnectedToSession())
        return 0x20;
    CRITICAL_SECTION *lpCriticalSection = &provider->dataLock;
    EnterCriticalSection(&provider->dataLock);
    MyPlayerDesc *f24_playerList = provider->f24_playerList;
    if ( !f24_playerList ) {
        LeaveCriticalSection(lpCriticalSection);
        return 0x20;
    }
    unsigned int f8_playersSlot = a2_slot_m2_m3;
    if ( a2_slot_m2_m3 == net_CurrentPlayer ) {
        f8_playersSlot = provider->f226_curPlayer.playersSlot;
    } else if ( a2_slot_m2_m3 == net_HostPlayer ) {
        for (int i = 0; i < provider->f186_sessionDesc.totalMaxPlayers; ++i) {
            MyPlayerDesc *curDesc = &provider->f24_playerList[i];
            if (!curDesc->isJoined()) continue;
            if (!curDesc->isHost()) continue;
            f8_playersSlot = curDesc->f35_slotNo;
            break;
        }
        if ( f8_playersSlot == net_HostPlayer )
        {
            _log("Mldplay::GetPlayerDesc:-Internal Error No Host found\n");
            LeaveCriticalSection(lpCriticalSection);
            return 0x20;
        }
    }
    if (f8_playersSlot >= provider->f186_sessionDesc.totalMaxPlayers ) {
        _log("MLDPlay::GetPlayerAddress Error:-Player Index isn't in a valid range.\n");
        LeaveCriticalSection(lpCriticalSection);
        return 0x20;
    }
    MyPlayerDesc *v7_desc = &f24_playerList[f8_playersSlot];
    if (!v7_desc->isJoined()) {
        _log("MLDPlay::GetPlayerAddress Error:-PlayerNo isnot valid.\n");
        LeaveCriticalSection(lpCriticalSection);
        return 0x20;
    }
    if ( a3_pAddr && *a4_pSize >= sizeof(MyPlayerSubDesc) ) {
        *a3_pAddr = v7_desc->f36_subDesc;
        *a4_pSize = sizeof(MyPlayerSubDesc);
        LeaveCriticalSection(lpCriticalSection);
        return 2;
    } else {
        *a4_pSize = sizeof(MyPlayerSubDesc);
        LeaveCriticalSection(lpCriticalSection);
        return 0x10;
    }
}

int MLDPlay::GetPlayerInfo(MLDPLAY_PLAYERINFO *a2_pInfoArr) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::GetPlayerInfo Error:-Not Initialised\n");
        return 0;
    }
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) {
        _log("MLDPlay::GetPlayerInfo Error:-No Service Provider\n");
        return 0;
    }
    if (!a2_pInfoArr) {
        _log("MLDPlay::GetPlayerInfo Error:-Null pointer passed\n");
        return 0;
    }
    if (!provider->f226_curPlayer.isConnectedToSession()) {
        _log("MLDPlay::GetPlayerInfo Error:-Not Connected to Session\n");
        return 0;
    }
    struct _RTL_CRITICAL_SECTION *p_f8_dataLock = &provider->dataLock;
    EnterCriticalSection(&provider->dataLock);
    MyPlayerDesc *f24_curDesc = provider->f24_playerList;
    if (f24_curDesc) {
        unsigned int v5_i = 0;
        if (provider->f186_sessionDesc.totalMaxPlayers) {
            MLDPLAY_PLAYERINFO *v6_dstPos = a2_pInfoArr;
            do {
                if (f24_curDesc->isJoined()) {
                    v6_dstPos->f0_flags = f24_curDesc->flags & 0xF0 | 1;
                    v6_dstPos->f26_playerId_slot = f24_curDesc->f20_playerId_slot;
                    v6_dstPos->f5_slotNo = f24_curDesc->f35_slotNo;
                    v6_dstPos->dword_1 = f24_curDesc->field_24;
                    wcscpy(v6_dstPos->f6_shortName, f24_curDesc->f0_playername);
                } else {
                    v6_dstPos->f0_flags = 0;
                    v6_dstPos->dword_1 = 0;
                    wcscpy(v6_dstPos->f6_shortName, L"");
                }
                ++v5_i;
                ++f24_curDesc;
                ++v6_dstPos;
            } while (v5_i < provider->f186_sessionDesc.totalMaxPlayers);
            p_f8_dataLock = &provider->dataLock;
        }
    }
    LeaveCriticalSection(p_f8_dataLock);
    return 1;
}

int MLDPlay::EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) {
    if (!this->fc_hasHandler) {
        _log("MLDPlay::EnumerateNetworkMediums Error:-Not Initialised\n");
        return 0x20;
    }
    NetworkServiceProvider *provider = net::call_new<DPlay>();
    if (!provider) {
        _log("MLDPlay::EnumerateNetworkMediums Error:-Couldnot create Temporary Service Provider\n");
        return 0x20;
    }
    if (!provider->Startup(this->f8_messageHandler)) {
        net::operator_delete(provider);
        return 0x20;
    }
    int result = provider->EnumerateNetworkMediums(a2, a3_dataBuf, a4_pSize);
    provider->ShutDown();
    net::operator_delete(provider);
    return result;
}

int MLDPlay::CreateNetworkAddress(DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
                                  MyDPlayCompoundAddress *a4_outAddr, unsigned int *a5_outSize) {
    if ( !this->fc_hasHandler || !a2_elements || !a3_elementCount )
        return 0x20;
    NetworkServiceProvider *provider;
    if ( *(GUID *) a2_elements->lpData == BFSPGUID_TCPIP) {
        provider = net::call_new<BullfrogNET>();
    } else if ( *(GUID *) a2_elements->lpData == BFSPGUID_IPX) {
        provider = net::call_new<BullfrogNET>();
    } else {
        provider = net::call_new<DPlay>();
    }
    if ( !provider ) return 0x20;
    if (!provider->Startup(this->f8_messageHandler)) {
        net::operator_delete(provider);
        return 0x20;
    }
    int result = provider->CreateCompoundAddress(a2_elements, a3_elementCount, a4_outAddr, a5_outSize);
    provider->ShutDown();
    net::operator_delete(provider);
    return result;
}

void MLDPlay::AddPacketToMemoryQueue(struct MLDPLAY_SYSTEMQUEUE *a2_queue, void *a3_data, unsigned int a4_copySize,
                                     unsigned int a5_dataSize) {
    if (!this->fc_hasHandler) return;
    if (!this->f4_pNetworkServiceProvider) return;
    MLDPLAY_SYSTEMQUEUE::addEntry(a2_queue, a3_data, a4_copySize, a5_dataSize);
}

void MLDPlay::DestroyMemoryQueue(struct MLDPLAY_SYSTEMQUEUE *a2_queue) {
    if (!this->fc_hasHandler) return;
    if (!this->f4_pNetworkServiceProvider) return;
    MLDPLAY_SYSTEMQUEUE::release(a2_queue);
}

MLDPLAY_SYSTEMQUEUE_Entry *MLDPlay::ReadPacketHeadFromMemoryQueue(MLDPLAY_SYSTEMQUEUE *a2_queue) {
    if (!this->fc_hasHandler) return NULL;
    if (!this->f4_pNetworkServiceProvider) return NULL;
    return MLDPLAY_SYSTEMQUEUE::getFirst(a2_queue);
}

void MLDPlay::RemovePacketFromMemoryQueue(MLDPLAY_SYSTEMQUEUE *a2_queue, MLDPLAY_SYSTEMQUEUE_Entry *Block) {
    if (!this->fc_hasHandler) return;
    if (!this->f4_pNetworkServiceProvider) return;
    MLDPLAY_SYSTEMQUEUE::removeEntry(a2_queue, Block);
}

void MLDPlay::SetLatency(unsigned int a2_latency) {
    if (!this->fc_hasHandler) return;
    if (!this->f4_pNetworkServiceProvider) return;
    // ignore
}

void MLDPlay::SetServerGrabber(const char *a2_host, uint16_t a3_port) {
    if (!this->fc_hasHandler) return;
    NetworkServiceProvider *provider = this->f4_pNetworkServiceProvider;
    if (!provider) return;
    provider->initGetHostByName(a2_host, a3_port);
}
