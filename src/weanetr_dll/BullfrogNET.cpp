//
// Created by DiaLight on 08.11.2024.
//

#include <WinSock2.h>
#include "BullfrogNET.h"
#include "DnsResolver.h"
#include "dplay.h"
#include "dplobby.h"
#include "protocol.h"
#include "messages.h"
#include "logging.h"
#include "globals.h"
#include "weanetr_memory.h"
#include "patches/logging.h"
#include "patches/micro_patches.h"

using namespace net;

char g_getHostByName_async_hostent[MAXGETHOSTSTRUCT];
int g_getHostByName_async_isComplete;

MySocket g_EnumerateSessions_lobbySock_dst;
mmtime_tag g_EnumerateSessions_sysTime_0;
mmtime_tag g_EnumerateSessions_sysTime_1;


int BullfrogNET::Startup(MessageHandlerType handler) {
    if (this->f565_recvdData) {
        net::_free(this->f565_recvdData);
        this->f565_recvdData = NULL;
    }
    this->f56d_pAddress = net::call_new<DnsResolver>();
    if (this->f56d_pAddress == NULL) return 1;
    if (this->f56d_pAddress->wsaStartup()) {
        net::call_delete<DnsResolver>(this->f56d_pAddress);
        this->f56d_pAddress = NULL;
        return 1;
    }
    NetworkServiceProvider::Startup(handler);
    this->f20_isServiceProviderInitialized = 1;
    return 1;
}

int BullfrogNET::ShutDown() {
    if ( !this->f20_isServiceProviderInitialized ) return 0;
    _log("\tBullfrogNET::ShutDown Called\n");
    this->waitResetSessions(1);
    if (this->f226_curPlayer.isConnectedToSession()) {
        NetworkServiceProvider::Destroy();
        this->getHostByname_destroy();
        _log("\tBullfrogNET Session Destroyed\n");
    }
    if ( this->f56d_pAddress ) {
        WSACleanup();
        net::call_delete<DnsResolver>(this->f56d_pAddress);
        this->f56d_pAddress = NULL;
    }
    NetworkServiceProvider::ShutDown();
    this->f20_isServiceProviderInitialized = FALSE;
    if (f30_dPlayAddr != NULL) {
        net::_free(f30_dPlayAddr);
        this->f30_dPlayAddr = NULL;
    }
    if ( this->f565_recvdData != NULL) {
        net::_free(this->f565_recvdData);
        this->f565_recvdData = NULL;
    }
    memset(this->f5E3_g_addr, 0, 0xD0u);
    memset(&this->f6B3_myaddr, 0, sizeof(this->f6B3_myaddr));
    return 0;
}

void BullfrogNET::getHostByname_destroy() {
    if (this->f5db_getHostByName_async_hWnd == NULL) return;
    WSACancelAsyncRequest(this->h5df_getHostByName_async_taskHandle);
    DestroyWindow(this->f5db_getHostByName_async_hWnd);
    UnregisterClassA(this->f5bb_lpClassName, GetModuleHandleA(NULL));
    this->f5db_getHostByName_async_hWnd = NULL;
    this->h5df_getHostByName_async_taskHandle = NULL;
}

void BullfrogNET::clearSessionList() {
    this->getHostByname_destroy();
    ListEntry_SessionDesc *f593_sessionList = this->f593_sessionList;
    while ( f593_sessionList ) {
        ListEntry_SessionDesc *toFree = f593_sessionList;
        f593_sessionList = f593_sessionList->fA8_next;
        net::_free(toFree);
    }
    this->f593_sessionList = NULL;
}

int BullfrogNET::waitResetSessions(int a2_clearSessions) {
    MySocket_close(&this->f57B_enumerateSessions_sock);
    int isThreadAlive = 1;
    do {
        EnterCriticalSection(&this->dataLock);
        if ( this->f59F_enumerateSessions_hThread == INVALID_HANDLE_VALUE )
            isThreadAlive = 0;
        LeaveCriticalSection(&this->dataLock);
        SwitchToThread();  // fix for single thread affinity
    } while ( isThreadAlive );
    this->f58F_flags = 0;
    if ( a2_clearSessions )
        this->clearSessionList();
    this->f57B_enumerateSessions_sock.portBe = 0;
    this->f57B_enumerateSessions_sock.socket = INVALID_SOCKET;
    this->f57B_enumerateSessions_sock.ipv4 = 0;
    return 0;
}

int BullfrogNET::BuildSession(
        MessageHandlerType handler, GUID *guid, char *a4_outNGLD,
        DWORD *a5_outPlayers, wchar_t *a6_outGameName, wchar_t *a7_outPlayerName,
        int a8_totalMaxPlayers, int a9_ignore) {
    int hasHostOrJoin = 0;
    int result = 0x20;
    const char *CommandLineA = GetCommandLineA();
    char *CommandLineA_1 = (char *)CommandLineA;
    memset(&this->f6B3_myaddr, 0, sizeof(this->f6B3_myaddr));
    if ( !CommandLineA )
        return result;
    memset(this->f5E3_g_addr, 0, 0xD0u);
    const char *addr_flag = strstr(CommandLineA, "/h tcp");
    BOOL isHost = FALSE;
    if ( addr_flag ) {
        hasHostOrJoin = 1;
        isHost = TRUE;
    } else {
        addr_flag = strstr(CommandLineA_1, "/j tcp");
        if ( addr_flag ) {
            isHost = FALSE;
            hasHostOrJoin = 1;
        }
    }
    if ( !hasHostOrJoin ) return result;
    char *buf_addr_ = (char *)net::_malloc(0x100u);
    char *buf_addr = buf_addr_;
    if ( !buf_addr_ ) return 0x20;
    memset(buf_addr_, 0, 0x100u);
    if ( !isHost ) {
        const char *addr_valPos = &addr_flag[strlen("/j tcp ")];
        char addr_ch = *addr_valPos;
        if ( *addr_valPos != ' ' ) {
            char *buf_addr_pos_ = buf_addr_;
            do {
                if ( !addr_ch ) break;
                ++addr_valPos;
                *buf_addr_pos_++ = addr_ch;
                addr_ch = *addr_valPos;
            } while ( *addr_valPos != ' ' );
        }
    }
    char *buf_playerName = (char *)net::_malloc(0x100u);
    char *_buf_playerName = buf_playerName;
    if ( !buf_playerName ) {
        net::_free(buf_addr_);
        return 0x20;
    }
    memset(buf_playerName, 0, 0x100u);
    if (char *name_flag = strstr(CommandLineA_1, "/n")) {
        char *name_valPos = &name_flag[strlen("/n")];
        int name_idx = 0;
        for (char name_ch = *name_valPos; name_ch != '/'; ++name_valPos ) {
            if ( !name_ch ) break;
            buf_playerName[name_idx] = name_ch;
            name_ch = name_valPos[1];
            ++name_idx;
        }
        buf_playerName[name_idx] = 0;
        if ( a4_outNGLD )
            strcpy(a4_outNGLD + 128, buf_playerName);
        strcpy(this->f663_n_addr, buf_playerName);
    }
    memset(a4_outNGLD, 0, 0xD0u);
    if (char *g_flag = strstr(CommandLineA_1, "/g")) {
        char *g_valPos = &g_flag[strlen("/g")];
        int g_idx = 0;
        for (char g_ch = *g_valPos; g_ch != '/'; ++g_valPos ) {
            if ( !g_ch )
                break;
            if ( a4_outNGLD )
                a4_outNGLD[g_idx] = g_ch;
            this->f5E3_g_addr[g_idx] = *g_valPos;
            g_ch = g_valPos[1];
            ++g_idx;
        }
        if ( a4_outNGLD )
            a4_outNGLD[g_idx] = 0;
        this->f5E3_g_addr[g_idx] = 0;
    }
    if (char *l_flag = strstr(CommandLineA_1, "/l")) {
        char *l_valPos = &l_flag[strlen("/l")];
        int l_idx = 0;
        for (char l_ch = *l_valPos; l_ch != '/'; ++l_valPos ) {
            if ( !l_ch )
                break;
            if ( a4_outNGLD )
                a4_outNGLD[l_idx + 64] = l_ch;
            this->f623_l_addr[l_idx] = *l_valPos;
            l_ch = l_valPos[1];
            ++l_idx;
        }
        if ( a4_outNGLD )
            a4_outNGLD[l_idx + 64] = 0;
        this->f623_l_addr[l_idx] = 0;
    }
    if (char *d_flag = strstr(CommandLineA_1, "/d")) {
        char *d_valPos = &d_flag[strlen("/d")];
        int d_idx = 0;
        for (char d_ch = *d_valPos; d_ch != '/'; ++d_valPos ) {
            if ( !d_ch )
                break;
            if ( a4_outNGLD )
                a4_outNGLD[d_idx + 144] = d_ch;
            this->f673_SendMS_addr[d_idx] = *d_valPos;
            d_ch = d_valPos[1];
            ++d_idx;
        }
        if ( a4_outNGLD )
            a4_outNGLD[d_idx + 144] = 0;
        this->f673_SendMS_addr[d_idx] = 0;
    }
    if (char *boundIp_flag = strstr(CommandLineA_1, "/boundip")) {
        char *boundIp_valPos = &boundIp_flag[strlen("/boundip ")];
        int boundIp_idx = 0;
        for (char boundIp_ch = *boundIp_valPos; boundIp_ch != '/'; ++boundIp_valPos ) {
            if ( !boundIp_ch )
                break;
            this->f6B3_myaddr.f0_boundip[boundIp_idx] = boundIp_ch;
            boundIp_ch = boundIp_valPos[1];
            ++boundIp_idx;
        }
        this->f6B3_myaddr.f0_boundip[boundIp_idx] = 0;
        this->f6B3_myaddr.f14_ipv4 = inet_addr(this->f6B3_myaddr.f0_boundip);
    }
    {
        const char *lobby_pos = "LOBBY";
        wchar_t *gameName_pos = a6_outGameName;
        for (char lobby_ch = lobby_pos[0]; lobby_ch; ++lobby_pos ) {
            *gameName_pos = lobby_ch;
            lobby_ch = lobby_pos[1];
            ++gameName_pos;
        }
        *gameName_pos = 0;
    }

    {
        char *buf_playerName_pos = buf_playerName;
        wchar_t *playerName_pos = a7_outPlayerName;
        for (char playerName_ch = *buf_playerName; playerName_ch; ++buf_playerName_pos ) {
            *playerName_pos = playerName_ch;
            playerName_ch = buf_playerName_pos[1];
            ++playerName_pos;
        }
        *playerName_pos = 0;
    }

    DPCOMPOUNDADDRESSELEMENT *elements = (DPCOMPOUNDADDRESSELEMENT *) net::_malloc(sizeof(DPCOMPOUNDADDRESSELEMENT) * 20);
    if (!elements) {
        net::_free(buf_addr);
        net::_free(_buf_playerName);
        return result;
    }
    elements->guidDataType.Data1 = 0xC508D4E1;
    *(DWORD *) &elements->guidDataType.Data2 = 0x11D2E761;
    *(DWORD *) elements->guidDataType.Data4 = 0x5000DF91;
    *(DWORD *) &elements->guidDataType.Data4[4] = 0x4D530C04;
    elements->dwDataSize = 16;
    elements->lpData = &BFSPGUID_TCPIP;

    wchar_t waddr[128];
    {
        memset(waddr, 0, sizeof(waddr));
        wchar_t *waddr_pos = waddr;
        char *buf_caddr_pos = buf_addr;
        for (char waddr_ch = *buf_caddr_pos; waddr_ch; ++buf_caddr_pos) {
            *waddr_pos = waddr_ch;
            waddr_ch = buf_caddr_pos[1];
            ++waddr_pos;
        }
        *waddr_pos = 0;
    }
    MyAddr addr;
    addr.f0_pAddr = waddr;
    addr.f4_size = 2 * wcslen(waddr) + 2;
    addr.f8_port = 7575;
    elements[1].guidDataType = BFAID_INet;
    elements[1].dwDataSize = 0xA;
    elements[1].lpData = &addr;

    // bfnet=10003DE0 dplay=10008180
    size_t caddr_size = 0;
    if (this->CreateCompoundAddress(elements, 2, NULL, &caddr_size) != 16) {
        net::_free(elements);

        net::_free(buf_addr);
        net::_free(_buf_playerName);
        return result;
    }
    MyDPlayCompoundAddress *compoundAddress = (MyDPlayCompoundAddress *) net::_malloc(caddr_size);
    if (!compoundAddress) {
        net::_free(elements);

        net::_free(buf_addr);
        net::_free(_buf_playerName);
        return result;
    }

    if (this->CreateCompoundAddress(elements, 2, compoundAddress, &caddr_size) != 2) {
        net::_free(compoundAddress);

        net::_free(elements);

        net::_free(buf_addr);
        net::_free(_buf_playerName);
        return result;
    }
    if (!this->SetupConnection(compoundAddress, guid, NULL)) {
        net::_free(compoundAddress);

        net::_free(elements);

        net::_free(buf_addr);
        net::_free(_buf_playerName);
        return result;
    }
    if (isHost) {
        MySessionCredentials v68_cred;
        memset(&v68_cred, 0, sizeof(v68_cred));
        v68_cred.f4_dk2Version = 0;
        v68_cred.f0_credentialParameterSize = 0x30;
        v68_cred.f10_totalMaxPlayers = a8_totalMaxPlayers;
        v68_cred.f14__totalMaxPlayers2 = a8_totalMaxPlayers;
        v68_cred.field_18 = a9_ignore;
        int joinStatus;
        do {
            joinStatus = this->CreateSession(
                    a5_outPlayers,
                    a6_outGameName,
                    a7_outPlayerName,
                    &v68_cred,
                    0x404);
        } while (joinStatus == 1);  // connecting
        if (joinStatus == 2) {  // joined
            Sleep(3000u);
            result = 0x1000;
        }
    } else {

        struct MyGotASession {
            DWORD dword_0;
            int f4_present;
            MLDPLAY_SESSIONDESC f8_desc;
        };
        static_assert(sizeof(MyGotASession) == 0xAC);

        MyGotASession *v53_gas = (MyGotASession *) net::_malloc(sizeof(MyGotASession));
        if (v53_gas) {
            v53_gas->f4_present = 0;
            // bfnet=10002E20 dplay=100073D0
            int enumResult = this->EnumerateSessions(0, [](MLDPLAY_SESSIONDESC *a1_desc, void *arg) {
                auto *gas = (MyGotASession *) arg;
                if (gas && a1_desc) {
                    memcpy(&gas->f8_desc, a1_desc, sizeof(gas->f8_desc));
                    gas->f4_present = 1;
                }
                _log("GOT A SESSION\n");
            }, 0x400, v53_gas);
            if (enumResult == 2 && v53_gas->f4_present) {
                MLDPLAY_SESSIONDESC *desc = &v53_gas->f8_desc;
                MySessionCredentials v68_cred;
                memset(&v68_cred, 0, sizeof(v68_cred));
                v68_cred.f0_credentialParameterSize = 0x30;
                v68_cred.f4_dk2Version = 0;
                int joinStatus;
                do {
                    joinStatus = this->JoinSession(
                            desc,
                            a5_outPlayers,
                            a7_outPlayerName,
                            &v68_cred
                    );
                } while (joinStatus == 1);  // connecting
                if (joinStatus == 2) {  // joined
                    result = 0x2000;
                }
            }
            net::_free(v53_gas);
        }
    }
    net::_free(compoundAddress);

    net::_free(elements);

    net::_free(buf_addr);
    net::_free(_buf_playerName);
    return result;
}

int BullfrogNET::SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guidApplication, void *a4_arg) {
    if ( !this->f20_isServiceProviderInitialized )
        return 0;
    this->waitResetSessions(1);
    _log("** BULLFROG SP -- RUNNING TCP / IP -- **\n");
    _log("** %s **\n", this->f56d_pAddress->f0_wsaData.szDescription);
    _log("** %s **\n", this->f56d_pAddress->f0_wsaData.szSystemStatus);
    _log("** MAX DATAGRAM SIZE = %d Class size %d**\n", this->f56d_pAddress->f0_wsaData.iMaxUdpDg, 1751);
    if ( !a2_dplayAddr )
        return 0;
    if ( this->f30_dPlayAddr )
        net::_free(this->f30_dPlayAddr);
    MyDPlayCompoundAddress *v6_dplayAddr = (MyDPlayCompoundAddress *) net::_malloc(sizeof(MyDPlayCompoundAddress) + a2_dplayAddr->f12_addr.f4_size);
    this->f30_dPlayAddr = v6_dplayAddr;
    if ( !v6_dplayAddr ) {
        _log("\tBullfrogNET::SetupConnection Error:-Failed to allocate Connection buffer\n");
        return 0;
    }
    memset(v6_dplayAddr, 0, sizeof(MyDPlayCompoundAddress) + a2_dplayAddr->f12_addr.f4_size);
    memcpy(this->f30_dPlayAddr, a2_dplayAddr, sizeof(MyDPlayCompoundAddress));
    this->f30_dPlayAddr->f12_addr.f0_pAddr = (wchar_t *)&this->f30_dPlayAddr[1];
    {
        wchar_t *v10_src_pos = a2_dplayAddr->f12_addr.f0_pAddr;
        char *v11_dst_pos = (char *) this->f30_dPlayAddr->f12_addr.f0_pAddr;
        while(true) {
            char v12_ch = *(char *)v10_src_pos++;
            *v11_dst_pos++ = v12_ch;
            if(!v12_ch) break;
        }
    }
    MyDPlayCompoundAddress *f30_dPlayAddr = this->f30_dPlayAddr;
    if ( !f30_dPlayAddr->f12_addr.f8_port )
        f30_dPlayAddr->f12_addr.f8_port = 7575;
    this->f30_dPlayAddr->f12_addr.f4_size = strlen((const char *)this->f30_dPlayAddr->f12_addr.f0_pAddr) + 1;
    this->f4_arg = a4_arg;

    this->f44_guidApplication = *a3_guidApplication;

    MyDPlayCompoundAddress *v14_dPlayAddr = this->f30_dPlayAddr;
    const char *v15_addr = (const char *) v14_dPlayAddr->f12_addr.f0_pAddr;
    if ( v15_addr )
        _log("** DEST ADDRESS %s\n", v15_addr);
    else
        _log("** DEST ADDRESS 255.255.255.255\n");
    _log("** DEST PORT    %d\n", this->f30_dPlayAddr->f12_addr.f8_port);
    return 1;
}

int BullfrogNET::EnumerateLocalServices(NetworkServiceProvider::ServiceEnumCallback a2_fun, void *a3_arg) {
    const wchar_t *serviceName = L"WinSock TCP/IP Internet Connection";
    size_t v4_nameLen = wcslen(serviceName);
    MyLocalService *v5_localService = (MyLocalService *) net::_malloc(sizeof(MyLocalService) + (v4_nameLen + 1) * sizeof(wchar_t) + sizeof(GUID));
    static_assert(0x3A == (2 + sizeof(GUID) + sizeof(MyLocalService)));
    if (!v5_localService) {
        _log("\tBullfrogNET::EnumerateLocalServices Error:-Couldnot allocate for service list\n");
        return 0;
    }

    memset(v5_localService, 0, sizeof(MyLocalService));
    v5_localService->f0_guid = BFSPGUID_TCPIP;
    v5_localService->f10_count = 1;
    v5_localService->f18_pName = v5_localService->f28_name;
    v5_localService->f20_addr = NULL;
    v5_localService->f14_addr_size = 0;
    v5_localService->f1C_next = NULL;
    wcscpy(v5_localService->f28_name, serviceName);
    GUID *v7_guid2 = (GUID *) &v5_localService->f28_name[wcslen(v5_localService->f28_name) + 1];
    *v7_guid2 = BFAID_INet;
    v5_localService->f24_pGuid = v7_guid2;
    size_t v8_addrSize = 2 * (wcslen(L"255.255.255.255") + 1) + sizeof(MyLocalServiceAddr);

    MyLocalServiceAddr *localServiceAddr = (MyLocalServiceAddr *) net::_malloc(v8_addrSize);
    if (!localServiceAddr) {
        _log("\tBullfrogNET::EnumerateLocalServices Error:-Couldnot allocate for connection\n");
        net::_free(v5_localService);
        return 0;
    }
    localServiceAddr->f0_signature[0] = 'B';
    localServiceAddr->f0_signature[1] = 'F';
    localServiceAddr->f2_guid = BFSPGUID_TCPIP;
    localServiceAddr->f12_addr.f4_size = 2 * (wcslen(L"255.255.255.255") + 1);
    localServiceAddr->f12_addr.f8_port = 7575;
    localServiceAddr->f12_addr.f0_pAddr = localServiceAddr->f22_addr;
    wcscpy(localServiceAddr->f22_addr, L"255.255.255.255");

    v5_localService->f14_addr_size = v8_addrSize;
    v5_localService->f20_addr = localServiceAddr;
    if (this->f20_isServiceProviderInitialized) {
        int result = 0;
        if (a2_fun) {
            a2_fun(
                    v5_localService,
                    v5_localService->f18_pName,
                    v5_localService->f24_pGuid,
                    v5_localService->f10_count,
                    a3_arg);
            result = 1;
        }
        net::_free(localServiceAddr);
        net::_free(v5_localService);
        return result;
    }

    if (!this->Startup(NULL)) {
        _log("\tBullfrogNET::EnumerateLocalServices Error:-Couldnot Initialise Service Provider\n");
        net::_free(localServiceAddr);
        net::_free(v5_localService);
        return 0;
    }

    int result = 0;
    if (a2_fun) {
        a2_fun(
                v5_localService,
                v5_localService->f18_pName,
                v5_localService->f24_pGuid,
                v5_localService->f10_count,
                a3_arg);
        result = 1;
    }
    net::_free(localServiceAddr);
    net::_free(v5_localService);

    this->ShutDown();
    return result;
}

int BullfrogNET::CreateSPSession(
        DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
        MySessionCredentials *a5_cred, int a6_flags) {
    if (!this->f30_dPlayAddr) {
        _log("\tBullfrogNET::CreateSPSession Error::No Connection Setup : hint use SetupConnection()\n");
        return 0x20;
    }
    this->waitResetSessions(1);
    if (!a5_cred) {
        _log("\tBullfrogNET::CreateSPSession Error::No Credentials specified\n");
        return 0x20;
    }
    if (a5_cred->f0_credentialParameterSize < 0x30u) {
        _log("\tBullfrogNET::CreateSPSession Error::Invalid Credentials parameters specified\n");
        return 0x20;
    }
    if (!a5_cred->f10_totalMaxPlayers) {
        _log("\tBullNET::CreateSPSession Error:-Must specify a number of max players allowed to log in\n");
        return 0x20;
    }
    struct mmtime_tag pmmt;
    pmmt.wType = 1;
    timeGetSystemTime(&pmmt, 0xCu);

    this->f571_joinSession_sock = {0, NULL, 0};

    MyDPlayCompoundAddress *f30_dPlayAddr = this->f30_dPlayAddr;
    if (!f30_dPlayAddr->f12_addr.f8_port)
        f30_dPlayAddr->f12_addr.f8_port = 7575;
    this->f571_joinSession_sock.portBe = this->f30_dPlayAddr->f12_addr.f8_port;
    int ipv4 = this->f6B3_myaddr.f14_ipv4;
    if (this->f56d_pAddress->connect(&this->f571_joinSession_sock, ipv4)) {
        _log("\tBullfrogNET::CreateSPSession Error:-Couldn't Create Socket (maybe socket port is in use)\n");
        return 0x20;
    }
    GUID guidInstance;
    this->genRandomGuid(&guidInstance);
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    this->f569_last_playerId_slot = {0};
    this->f186_sessionDesc.dk2Version = a5_cred->f4_dk2Version;
    this->f186_sessionDesc.flags = a6_flags;
    this->f186_sessionDesc.guidInstance = guidInstance;
    this->f186_sessionDesc.guidApplication = this->f44_guidApplication;
    this->f186_sessionDesc.totalMaxPlayers = a5_cred->f10_totalMaxPlayers;
    this->f186_sessionDesc.currentPlayers = 1;
    this->f186_sessionDesc.mapNameLen_mapPlayersCount = a5_cred->f20_mapNameLen_mapPlayersCount;
    this->f186_sessionDesc.mapNameHash = a5_cred->f24_mapNameHash;
    this->f186_sessionDesc.fileHashsum = a5_cred->f28_fileHashsum;
    this->f186_sessionDesc.cred_2C = a5_cred->field_2C;
    wcscpy(this->f186_sessionDesc.gameName, a3_gameName);
    this->f186_sessionDesc.sock = this->f571_joinSession_sock;
    this->f226_curPlayer.playersSlot = 0;
    MyPlayerDesc *f24_playerList = this->f24_playerList;
    this->f226_curPlayer.flags |= 3;
    this->f226_curPlayer.playerId = {0};
    f24_playerList->f20_playerId_slot = {0};
    this->f24_playerList->flags = this->f24_playerList->flags & 0xF0 | 1;
    this->f24_playerList->flags = this->f24_playerList->flags & 0xF | 0x10;
    MyPlayerSubDesc *p_f36_subDesc = &this->f24_playerList->f36_subDesc;
    p_f36_subDesc->f0_ipv4 = this->f571_joinSession_sock.ipv4;
    p_f36_subDesc->f4_portBe = this->f571_joinSession_sock.portBe;
    this->genRandomGuid(&p_f36_subDesc->f6_guidPlayer);
    wcscpy(this->f24_playerList->f0_playername, a4_playerName);
    *a2_outPlayers = 0;
    this->f226_curPlayer.playerId = {0};
    if (a5_cred->f1C_password) {
        wcscpy(this->f41F_password, a5_cred->f1C_password);
        this->f186_sessionDesc.flags |= 0x200;
    }
    _log(
            "\tBullfrogNET::CreateSPSession Success:- Created session for max players of %d Opened Port %d\n",
            a5_cred->f10_totalMaxPlayers,
            this->f30_dPlayAddr->f12_addr.f8_port);
    this->initGetHostByName("daphne.eagames.co.uk", 7575);
    this->startGetHostByNameAsync();
    return 2;
}

void BullfrogNET::genRandomGuid(GUID *guid) {
#pragma pack(push, 1)
    struct MyRandData {
        DWORD f0_ipv4;
        __int16 f4_port;
        DWORD f6_ms;
        char fA_hour;
        char fB_min;
        char fC_sec;
        char fD_mday;
        __int16 fE_rand;
    };
#pragma pack(pop)
    static_assert(sizeof(MyRandData) == 0x10);
    static_assert(sizeof(MyRandData) == sizeof(GUID));
    MyRandData *v2_guid = (MyRandData *)guid;
    guid->Data1 = this->f571_joinSession_sock.ipv4;
    v2_guid->f4_port = this->f571_joinSession_sock.portBe;
    BYTE *p_f6_ms = (BYTE *) &v2_guid->f6_ms;
    struct mmtime_tag sysTime;
    timeGetSystemTime(&sysTime, 0xCu);
    *(DWORD *)p_f6_ms = sysTime.u.ms;
    p_f6_ms += 4;
    ::time((time_t *const) &guid);
    struct tm *v4_localTime = ::localtime((time_t * const) &guid);
    *p_f6_ms++ = v4_localTime->tm_hour;
    *p_f6_ms++ = v4_localTime->tm_min;
    *p_f6_ms++ = v4_localTime->tm_sec;
    *p_f6_ms = v4_localTime->tm_mday;
    ::srand(::time(NULL));
    *(WORD *)(p_f6_ms + 1) = ::rand();
}

int BullfrogNET::startGetHostByNameAsync() {
    if ( !this->f45F_getHostByName_isPresent ) return 0;
    this->f6CB_sysTime.wType = 1;
    timeGetSystemTime(&this->f6CB_sysTime, 0xCu);
    memset(f5A7_dst_addrStr_by_getHostByName, 0, sizeof(f5A7_dst_addrStr_by_getHostByName));
    return this->getHostByName_async(this->f463_getHostByName_host);
}

int BullfrogNET::getHostByName_async(char *hostName) {
    memset(&g_getHostByName_async_hostent, 0, MAXGETHOSTSTRUCT);
    memset(f5A7_dst_addrStr_by_getHostByName, 0, sizeof(f5A7_dst_addrStr_by_getHostByName));
    WNDCLASSA WndClass;
    memset(&WndClass, 0, sizeof(WndClass));
    g_getHostByName_async_isComplete = 0;
    HMODULE hInstance = GetModuleHandleA(NULL);
    strcpy(this->f5bb_lpClassName, "MLHI");
//    WndClass.lpfnWndProc = (WNDPROC) BullfrogNET_wndProc_MLHI_getHostByName;
    WndClass.lpfnWndProc = [](HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        if ( Msg == 1 || Msg == 2 ) return 0;
        if ( Msg == 0x401 && !HIWORD(lParam) )
            g_getHostByName_async_isComplete = 1;
        return DefWindowProcA(hWnd, Msg, wParam, lParam);
    };
    WndClass.cbWndExtra = 30;
    WndClass.style = 0;
    WndClass.cbClsExtra = 0;
    WndClass.hInstance = hInstance;
    memset(&WndClass.hIcon, 0, 16);
    WndClass.lpszClassName = this->f5bb_lpClassName;
    if ( RegisterClassA(&WndClass) ) {
        this->f5db_getHostByName_async_hWnd = CreateWindowExA(
                0, this->f5bb_lpClassName, "MARK",
                0x80000000,
                0x80000000, 0x80000000,
                0x80000000, 0x80000000,
                NULL, NULL, hInstance, NULL
        );
    }
    if (!this->f5db_getHostByName_async_hWnd) {
        UnregisterClassA(this->f5bb_lpClassName, hInstance);
        return FALSE;
    }
    // 0x401 - message that will be received by hWnd
    this->h5df_getHostByName_async_taskHandle = WSAAsyncGetHostByName(
            this->f5db_getHostByName_async_hWnd,
            0x401u,
            hostName,
            g_getHostByName_async_hostent,
            MAXGETHOSTSTRUCT
    );
    return TRUE;
}

void BullfrogNET::JoinSession_proc() {
    u_long argp = 0;
    int exitLoop = 0;
    _log("\tBullfrogNET::Starting JoinSession Thread\n");

    ioctlsocket(this->f571_joinSession_sock.socket, 0x8004667E, &argp);
    MyPacket_8_PlayerAdded *v1_packet = (MyPacket_8_PlayerAdded *) net::operator_new(0x400u);
    unsigned int status;
    while ( !exitLoop ) {
        MySocket srcSock;
        status = MySocket_recv(v1_packet, 1024, &this->f571_joinSession_sock, &srcSock);
        if ( status == -1 ) {
            exitLoop = 1;
            switch ( GetLastError() ) {
                case 0x2714u:
                    _log("\tBullfrogNET:: The (blocking) call was canceled using WSACancelBlockingCall.\n");
                    break;
                case 0x271Eu:
                    _log(
                            "\tBullfrogNET:: The fromlen argument was invalid: the from buffer was too small to accommodate the peer address.\n");
                    break;
                case 0x2726u:
                    _log("\tBullfrogNET:: A blocking Windows Sockets operation is in progress.\n");
                    break;
                case 0x2733u:
                    _log("\tBullfrogNET:: The socket is marked as nonblocking and the recvfrom operation would block.\n");
                    exitLoop = 0;
                    break;
                case 0x2736u:
                    _log("\tBullfrogNET:: The descriptor is not a socket.\n");
                    break;
                case 0x2738u:
                    _log("\tBullfrogNET:: The datagram was too large to fit into the specified buffer and was truncated.\n");
                    exitLoop = 0;
                    break;
                case 0x273Du:
                    _log("\tBullfrogNET:: MSG_OOB was specified, but the socket is not of type SOCK_STREAM.\n");
                    break;
                case 0x2742u:
                    _log("\tBullfrogNET:: The Windows Sockets implementation has detected that the network subsystem has failed.\n");
                    break;
                case 0x2745u:
                    _log("\tBullfrogNET:: The virtual circuit was aborted due to timeout or other failure.\n");
                    break;
                case 0x2746u:
                    _log("\tBullfrogNET:: The virtual circuit was reset by the remote side.\n");
                    break;
                case 0x2749u:
                    _log("\tBullfrogNET:: The socket is not connected (SOCK_STREAM only).\n");
                    break;
                case 0x274Au:
                    _log(
                            "\tBullfrogNET:: The socket has been shut down; it is not possible to recvfrom on a socket after shutdown has"
                            " been invoked with how set to 0 or 2.\n");
                    break;
                case 0x276Du:
                    _log("\tBullfrogNET:: A successful WSAStartup must occur before using this function.\n");
                    break;
                default:
                    break;
            }
            continue;
        }
        EnterCriticalSection(&this->dataLock);
        if ( status >= 0xC
             && v1_packet->f0_hdr.signature == PacketHeader::MAGIC
             && v1_packet->f0_hdr.packetTy == MyPacket_8_PlayerAdded::ID
             && status >= 0x60 ) {
            if (!this->f226_curPlayer.isConnectedToSession()
                 && !memcmp(&v1_packet->f10_guidApplication, &this->f44_guidApplication, 0x10u)
                 && !memcmp(&v1_packet->f20_guidInstance, &this->f186_sessionDesc.guidInstance, 0x10u)
                 && !memcmp(&v1_packet->f30_guidPlayer, &this->f34_guidPlayer, 0x10u) ) {
                this->f54_host_ipv4 = srcSock.ipv4;
                this->f58_host_portBe = srcSock.portBe;
                this->f226_curPlayer.playerId = v1_packet->f40_playerId;
                this->f28_host_playerId = v1_packet->f44_hostPlayerId;
                this->f226_curPlayer.flags |= 2;
                this->f186_sessionDesc.currentPlayers = v1_packet->f4C_currentPlayers;
                this->f186_sessionDesc.totalMaxPlayers = v1_packet->f48_totalMaxPlayers;
                int playerSlot = this->__getHiWord(v1_packet->f40_playerId);
                MyPlayerDesc *f24_playerList = this->f24_playerList;
                this->f226_curPlayer.playersSlot = playerSlot;
                exitLoop = 1;
                f24_playerList[playerSlot].flags = f24_playerList[playerSlot].flags & 0xF0 | 1;
                this->f24_playerList[this->f226_curPlayer.playersSlot].f20_playerId_slot = this->f226_curPlayer.playerId;
                _log("GOT A JOINED SESSION PACKET\n");
            }
        }
        LeaveCriticalSection(&this->dataLock);
    }
    net::operator_delete(v1_packet);
    _log("\tBullfrogNET::Ending JoinSession Thread\n");
    EnterCriticalSection(&this->dataLock);
    this->f59B_joinSession_hThread = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&this->dataLock);
}

void BullfrogNET::waitForThreadExit_JoinSession() {
    int isThreadAlive = 1;
    do {
        EnterCriticalSection(&this->dataLock);
        if ( this->f59B_joinSession_hThread == INVALID_HANDLE_VALUE )
            isThreadAlive = 0;
        LeaveCriticalSection(&this->dataLock);
        SwitchToThread();  // fix for single thread affinity
    } while ( isThreadAlive );
}

int BullfrogNET::JoinSPSession(
        MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount,
        wchar_t *a4_playerName, MySessionCredentials *a5_cred) {
    int v19_isConnected = 0;
    if ( !a2_desc ) {
        _log("\tBullfrogNET::JoinSPSession Error:-session ptr passed is NULL\n");
        return 0x20;
    }
    this->waitResetSessions(1);
    if ( !this->f30_dPlayAddr ) {
        _log("\tBullfrogNET::JoinSPSession Error:-No Connection setup, (hint:Try calling SetupConnection)\n");
        return 0x20;
    }
    MySessionCredentials *v20_cred = NULL;
    if ( (a2_desc->flags & 0x200) != 0 ) {
        if ( !a5_cred ) {
            _log("\tBullfrogNET::JoinSPSession Error:-Must specify Credentials\n");
            return 0x200;
        }
        v20_cred = a5_cred;
        if ( a5_cred->f0_credentialParameterSize < 0x30u ) {
            _log("\tBullfrogNET::JoinSPSession Error:-Invalid Credentials Passed\n");
            return 0x20;
        }
        if ( !a5_cred->f1C_password ) {
            _log("\tBullfrogNet::JoinSPSession Error:-Invalid Password\n");
            return 0x800;
        }
        wcscpy(this->f41F_password, a5_cred->f1C_password);
    }
    if ( a5_cred )
        v20_cred = a5_cred;

    this->f571_joinSession_sock = {0, NULL, 0};
    if ( this->f56d_pAddress->connect(&this->f571_joinSession_sock, this->f6B3_myaddr.f14_ipv4) ) {
        _log("\tBullfrogNET::JoinSPSession Error:-Couldn't Create Socket (maybe socket port is in use)\n");
        return 0x20;
    }
    MyPacket_7_Join addPlayerPacket;
    memset(&addPlayerPacket, 0, sizeof(addPlayerPacket));
    addPlayerPacket.f0_hdr.signature = PacketHeader::MAGIC;
    addPlayerPacket.f0_hdr.packetTy = MyPacket_7_Join::ID;

    addPlayerPacket.f10_guidApplication = this->f44_guidApplication;
    addPlayerPacket.f20_guidInstance = a2_desc->guidInstance;

    wcscpy(addPlayerPacket.f40_playerName, a4_playerName);
    if ( (a2_desc->flags & 0x200) != 0 )
        wcscpy(addPlayerPacket.f60_password, this->f41F_password);
    this->genRandomGuid(&addPlayerPacket.f30_guidPlayer);

    this->f34_guidPlayer = addPlayerPacket.f30_guidPlayer;
    HANDLE v11_hThread = (HANDLE) _beginthread([](void *arg) {
        auto *self = (BullfrogNET *) arg;
        self->JoinSession_proc();
    }, 0, this);
    this->f59B_joinSession_hThread = v11_hThread;
    if ( v11_hThread == INVALID_HANDLE_VALUE ) {
        MySocket_close(&this->f571_joinSession_sock);
        _log("\tBullfrogNET::JoinSPSession Error:-Couldn't Create Thread\n");
        return 0x20;
    }
    memset(&this->f226_curPlayer, 0, 0x2Cu);
    this->f226_curPlayer.f2C = 0;
    this->f186_sessionDesc.dk2Version = v20_cred->f4_dk2Version;
    this->f186_sessionDesc.flags = a2_desc->flags;

    this->f186_sessionDesc.guidInstance = a2_desc->guidInstance;
    this->f186_sessionDesc.guidApplication = this->f44_guidApplication;
    this->f186_sessionDesc.totalMaxPlayers = a2_desc->totalMaxPlayers;
    this->f186_sessionDesc.currentPlayers = a2_desc->currentPlayers;
    this->f186_sessionDesc.mapNameLen_mapPlayersCount = a2_desc->mapNameLen_mapPlayersCount;
    this->f186_sessionDesc.mapNameHash = a2_desc->mapNameHash;
    this->f186_sessionDesc.fileHashsum = a2_desc->fileHashsum;
    this->f186_sessionDesc.cred_2C = a2_desc->cred_2C;
    wcscpy(this->f186_sessionDesc.gameName, a2_desc->gameName);
    this->f186_sessionDesc.sock = this->f571_joinSession_sock;

    struct mmtime_tag startTime;
    startTime.wType = 1;
    struct mmtime_tag curTime;
    curTime.wType = 1;
    struct mmtime_tag lastSendTime;
    lastSendTime.wType = 1;
    timeGetSystemTime(&startTime, 0xCu);
    timeGetSystemTime(&curTime, 0xCu);
    timeGetSystemTime(&lastSendTime, 0xCu);

    MySocket a2_to = a2_desc->sock;
    MySocket_send(&this->f571_joinSession_sock, &a2_to, &addPlayerPacket, sizeof(MyPacket_7_Join));
    while ((curTime.u.ms - startTime.u.ms) < 60000) {
        timeGetSystemTime(&curTime, 0xCu);
        struct mmtime_tag curTime2;
        curTime2.wType = 1;
        timeGetSystemTime(&curTime2, 0xCu);
        EnterCriticalSection(&this->dataLock);
        if (this->f226_curPlayer.isConnectedToSession())
            v19_isConnected = 1;
        LeaveCriticalSection(&this->dataLock);
        if ( v19_isConnected ) {
            EnterCriticalSection(&this->dataLock);
            *a3_outPlayerCount = this->f226_curPlayer.playersSlot;
            this->initGetHostByName("daphne.eagames.co.uk", 7575);
            this->startGetHostByNameAsync();
            int f8_playersSlot = this->f226_curPlayer.playersSlot;
            this->f226_curPlayer.flags &= ~1;
            wcscpy(this->f24_playerList[f8_playersSlot].f0_playername, a4_playerName);
            LeaveCriticalSection(&this->dataLock);
            _log(
                    "\tBullfrogNET::JoinSPSession Success:- Player ID = %d Slot no %d Opened Port %d\n",
                    this->f226_curPlayer.playerId,
                    this->f226_curPlayer.playersSlot,
                    this->f571_joinSession_sock.portBe);
            waitForThreadExit_JoinSession();
            return 2;
        }
        if (curTime2.u.ms - lastSendTime.u.ms >= 500 ) {
            MySocket_send(&this->f571_joinSession_sock, &a2_to, &addPlayerPacket, sizeof(MyPacket_7_Join));
            lastSendTime.wType = 1;
            timeGetSystemTime(&lastSendTime, 0xCu);
        }
    }
    MySocket_close(&this->f571_joinSession_sock);
    waitForThreadExit_JoinSession();
    return 0x20;
}

void BullfrogNET::DestroyPlayer() {
    int f3C_flags = 0;
    int v17_isDestroySuccess = 0;
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tBullfrogNET::DestroyPlayer Error:-Service Provider Not Initialised\n");
        return;
    }
    if (!this->f226_curPlayer.isConnectedToSession()) {
        _log("\tBullfrogNET::DestroyPlayer Error:-Not Connected to Session\n");
        return;
    }

    EnterCriticalSection(&this->dataLock);
    if (this->f226_curPlayer.isHost()) {
        f3C_flags = this->f186_sessionDesc.flags;
        this->EnableNewPlayers(FALSE);
        if (this->f186_sessionDesc.currentPlayers < 2u) {
            v17_isDestroySuccess = 1;
            this->f226_curPlayer.flags &= ~2u;
            _log("\tBullfrogNET::DestroyPlayer Success\n");
        }
    }
    LeaveCriticalSection(&this->dataLock);

    if (v17_isDestroySuccess != 0) return;
    if (this->f226_curPlayer.isHost()) {
        PlayerId f4_playerId = this->f226_curPlayer.playerId;
        --this->f186_sessionDesc.currentPlayers;
        this->schedulePlayersChangePacket(MyPacket_9_PlayerLeave::ID, f4_playerId, this->f226_curPlayer.playersSlot, NULL, 0);
        if ((this->f186_sessionDesc.flags & 4) == 0) {
            Sleep(4000u);
            return;
        }
        for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
            MyPlayerDesc *f24_playerList = &this->f24_playerList[i];
            char f34_flags = f24_playerList->flags;
            if ((f34_flags & 0xF) == 0) continue;  // 0x01: player joined
            if ((f34_flags & 0xF0) != 0) continue;  // 0x10: is host
            _log(
                    "MIGRATING HOST, NEW HOST IS %d SlotNo %d\n",
                    f24_playerList->f20_playerId_slot,
                    f24_playerList->f35_slotNo);
            MySocket a2_to;
            a2_to.ipv4 = f24_playerList->f36_subDesc.f0_ipv4;
            a2_to.portBe = f24_playerList->f36_subDesc.f4_portBe;

            MyPacket_F_MigrateHost packet;
            packet.f0_hdr.signature = PacketHeader::MAGIC;
            packet.f0_hdr.packetTy = MyPacket_F_MigrateHost::ID;
            packet.f10__slotPacketCount = this->f5A_ackPacketCount_perPlayerSlot[f24_playerList->f35_slotNo]++;
            packet.f14_sessionFlags = f3C_flags;
            packet.f1C_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
            packet.f20_currentPlayers = this->f186_sessionDesc.currentPlayers;
            packet.f34_guidApplication = this->f186_sessionDesc.guidApplication;
            packet.f44_guidInstance = this->f186_sessionDesc.guidInstance;
            packet.f88__17 = 17;
            packet.f74_playerId_slot = f24_playerList->f20_playerId_slot;
            packet.f18_curPlayerId = this->f226_curPlayer.playerId;
            packet.f89_slotNo = f24_playerList->f35_slotNo;
            packet.fA3_last_playerId_slot = this->f569_last_playerId_slot;
            _log(
                    "SENDING UNIQUEPTR TO HOST %x %d, SLOT NO %d \n",
                    packet.fA3_last_playerId_slot,
                    packet.fA3_last_playerId_slot,
                    packet.fA3_last_playerId_slot.slotIdx);
            packet.f36_subDesc = f24_playerList->f36_subDesc;
            wcscpy(packet.f54_playername, f24_playerList->f0_playername);
            struct mmtime_tag sysTime;
            sysTime.wType = 1;
            struct mmtime_tag v19_sysTime;
            v19_sysTime.wType = 1;
            struct mmtime_tag v20_sysTime;
            v20_sysTime.wType = 1;
            timeGetSystemTime(&sysTime, 0xCu);
            timeGetSystemTime(&v19_sysTime, 0xCu);
            MySocket_send(&this->f571_joinSession_sock, &a2_to, &packet, sizeof(MyPacket_F_MigrateHost));
            while (v19_sysTime.u.ms - sysTime.u.ms < 4000) {
                struct mmtime_tag v23_sysTime;
                v23_sysTime.wType = 1;
                timeGetSystemTime(&v23_sysTime, 0xCu);
                timeGetSystemTime(&v19_sysTime, 0xCu);
                if (v23_sysTime.u.ms - v20_sysTime.u.ms >= 500) {
                    MySocket_send(&this->f571_joinSession_sock, &a2_to, &packet, sizeof(MyPacket_F_MigrateHost));
                    v20_sysTime.wType = 1;
                    timeGetSystemTime(&v20_sysTime, 0xCu);
                }
            }
            break;
        }
        if ((this->f186_sessionDesc.flags & 4) == 0) {
            Sleep(4000u);
        }
        return;
    }
    if (this->f186_sessionDesc.currentPlayers <= 1u) {
        EnterCriticalSection(&this->dataLock);
        this->f226_curPlayer.flags &= ~2u;
        LeaveCriticalSection(&this->dataLock);
        return;
    }
    struct mmtime_tag sysTime1;
    sysTime1.wType = 1;
    struct mmtime_tag v19SysTime;
    v19SysTime.wType = 1;
    struct mmtime_tag v20SysTime;
    v20SysTime.wType = 1;
    timeGetSystemTime(&sysTime1, 0xCu);
    timeGetSystemTime(&v19SysTime, 0xCu);
    timeGetSystemTime(&v20SysTime, 0xCu);

    MySocket a2To;
    a2To.portBe = 0;
    a2To.socket = NULL;
    a2To.portBe = this->f58_host_portBe;
    a2To.ipv4 = this->f54_host_ipv4;

    MyPacket_A_DestroyPlayer v24_packet;
    v24_packet.f0_hdr.signature = PacketHeader::MAGIC;
    v24_packet.f0_hdr.packetTy = MyPacket_A_DestroyPlayer::ID;
    v24_packet.f2C_guidApplication = this->f44_guidApplication;
    v24_packet.f3C_guidInstance = this->f186_sessionDesc.guidInstance;
    v24_packet.f4C_guidPlayer = this->f34_guidPlayer;

    v24_packet.f5C_playerId = this->f226_curPlayer.playerId;
    MySocket_send(&this->f571_joinSession_sock, &a2To, &v24_packet, sizeof(MyPacket_A_DestroyPlayer));
    while (v19SysTime.u.ms - sysTime1.u.ms < 4000) {
        timeGetSystemTime(&v19SysTime, 0xCu);
        struct mmtime_tag v23SysTime;
        v23SysTime.wType = 1;
        timeGetSystemTime(&v23SysTime, 0xCu);
        EnterCriticalSection(&this->dataLock);
        if (!this->f226_curPlayer.isConnectedToSession()) {
            _log("\tBullfrogNET::DestroyPlayer Success\n");
            v17_isDestroySuccess = 1;
        }
        LeaveCriticalSection(&this->dataLock);
        if (v17_isDestroySuccess)
            break;
        if (v23SysTime.u.ms - v20SysTime.u.ms >= 1000) {
            MySocket_send(&this->f571_joinSession_sock, &a2To, &v24_packet, sizeof(MyPacket_A_DestroyPlayer));
            v20SysTime.wType = 1;
            timeGetSystemTime(&v20SysTime, 0xCu);
        }
    }
}

int BullfrogNET::DestroySPSession() {
    if ( this->f20_isServiceProviderInitialized ) {
        if (this->f226_curPlayer.isConnectedToSession()) {
            this->listenThread_waitDestroy();
            this->DestroyPlayer();
            MySocket_close(&this->f571_joinSession_sock);
            this->f571_joinSession_sock = {0, NULL, 0};
            this->f226_curPlayer.flags &= ~2;
            memset(&this->f186_sessionDesc, 0, sizeof(this->f186_sessionDesc));
            memset(&this->f6B3_myaddr, 0, sizeof(this->f6B3_myaddr));
            this->getHostByname_destroy();
        } else {
            _log("\tBullfrogNET::DestroySPSession Error:-Not Connected to Session\n");
        }
    } else {
        _log("\tBullfrogNET::DestroySPSession Error:-Service Provider Not Initialised\n");
    }
    if (this->f565_recvdData ) {
        net::_free(this->f565_recvdData);
        this->f565_recvdData = NULL;
    }
    return 0;
}

void BullfrogNET::listenThread_waitDestroy() {
    if (this->f597_listenThread_hThread == INVALID_HANDLE_VALUE) return;
    MySocket_close(&this->f585_listenThread_sock);
    int isThreadAlive = 1;
    while ( isThreadAlive ) {
        EnterCriticalSection(&this->dataLock);
        if ( this->f597_listenThread_hThread == INVALID_HANDLE_VALUE )
            isThreadAlive = 0;
        LeaveCriticalSection(&this->dataLock);
        SwitchToThread();  // fix for single thread affinity
    }
    this->dword_5a3 = 0;
    _log("DESTROYED LISTEN THREAD\n");
}

void BullfrogNET::handleSessionPacket(MyPacket_6_sessionDesc *packet, mmtime_tag &sysTime) {
    MLDPLAY_SESSIONDESC *packetDesc = &packet->fC_desc;
    if (packetDesc->guidApplication != this->f44_guidApplication) return;
    if ((packetDesc->flags & 0x10) != 0) return;
    bool flag1 = (packetDesc->flags & 0x400) != 0;
    bool flag2 = (this->f58F_flags & 4) != 0;
    if(flag1 != flag2) return;

    if (!this->f593_sessionList) {
        ListEntry_SessionDesc *v10_newEntry2 = (ListEntry_SessionDesc *) net::_malloc(sizeof(ListEntry_SessionDesc));
        this->f593_sessionList = v10_newEntry2;
        if (v10_newEntry2) {
            v10_newEntry2->f0_desc = *packetDesc;
            this->f593_sessionList->fA4_timeMs = sysTime.u.ms;
            this->f593_sessionList->fA8_next = NULL;
        }
        return;
    }
    int gotANewSession = 1;
    ListEntry_SessionDesc *lastSession = NULL;
    for (ListEntry_SessionDesc *cur = this->f593_sessionList; cur; cur = cur->fA8_next) {
        if (cur->f0_desc.guidInstance == packetDesc->guidInstance) {
            gotANewSession = 0;
            cur->f0_desc = *packetDesc;
            cur->fA4_timeMs = sysTime.u.ms;
            break;
        }
        if (cur->f0_desc.sock.ipv4 == packetDesc->sock.ipv4) {
            _log("IP SESSIONS THE SAME\n");
            gotANewSession = 0;
            cur->f0_desc = *packetDesc;
            cur->fA4_timeMs = sysTime.u.ms;
            break;
        }
        lastSession = cur;
    }
    if (!gotANewSession) return;
    _log("GOT A NEW SESSION\n");
    if (!lastSession) return;
    ListEntry_SessionDesc *newEntry = (ListEntry_SessionDesc *) net::_malloc(sizeof(ListEntry_SessionDesc));
    if (!newEntry) return;
    lastSession->fA8_next = newEntry;
    newEntry->f0_desc = *packetDesc;
    newEntry->fA8_next = NULL;
    newEntry->fA4_timeMs = sysTime.u.ms;
}

void BullfrogNET::EnumerateSessions_proc() {
    int isConnectionClosed = 0;
    _log("\tBullfrogNET::Starting EnumerateSessions Thread\n");
    u_long argp = 0;
    ioctlsocket(this->f57B_enumerateSessions_sock.socket, 0x8004667E, &argp);

    PacketHeader *packet = (PacketHeader *) net::operator_new(1024);
    while ( !isConnectionClosed ) {
        MySocket v17_from;
        int v3_size = MySocket_recv(packet, 1024, &this->f57B_enumerateSessions_sock, &v17_from);
        unsigned int v4_size = v3_size;
        if ( v3_size == -1 ) {
            isConnectionClosed = 1;
            switch ( GetLastError() ) {
                case 0x2714u: _log("\tBullfrogNET:: The (blocking) call was canceled using WSACancelBlockingCall.\n"); break;
                case 0x271Eu: _log("\tBullfrogNET:: The fromlen argument was invalid: the from buffer was too small to accommodate the peer address.\n"); break;
                case 0x2726u: _log("\tBullfrogNET:: A blocking Windows Sockets operation is in progress.\n"); break;
                case 0x2733u: _log("\tBullfrogNET:: The socket is marked as nonblocking and the recvfrom operation would block.\n");
                    isConnectionClosed = 0;
                    break;
                case 0x2736u: _log("\tBullfrogNET:: The descriptor is not a socket.\n"); break;
                case 0x2738u: _log("\tBullfrogNET:: The datagram was too large to fit into the specified buffer and was truncated.\n");
                    isConnectionClosed = 0;
                    break;
                case 0x273Du: _log("\tBullfrogNET:: MSG_OOB was specified, but the socket is not of type SOCK_STREAM.\n"); break;
                case 0x2742u: _log("\tBullfrogNET:: The Windows Sockets implementation has detected that the network subsystem has failed.\n"); break;
                case 0x2745u: _log("\tBullfrogNET:: The virtual circuit was aborted due to timeout or other failure.\n"); break;
                case 0x2746u: _log("\tBullfrogNET:: The virtual circuit was reset by the remote side.\n"); break;
                case 0x2749u: _log("\tBullfrogNET:: The socket is not connected (SOCK_STREAM only).\n"); break;
                case 0x274Au: _log("\tBullfrogNET:: The socket has been shut down; it is not possible to recvfrom on a socket after shutdown has been invoked with how set to 0 or 2.\n"); break;
                case 0x276Du: _log("\tBullfrogNET:: A successful WSAStartup must occur before using this function.\n"); break;
                default: break;
            }
            continue;
        }
        if (v3_size == 0) {
            isConnectionClosed = 1;
            continue;
        }
        if (v3_size < 0) continue;
        struct mmtime_tag sysTime;
        sysTime.wType = 1;
        timeGetSystemTime(&sysTime, 0xCu);
        EnterCriticalSection(&this->dataLock);
        if ( v4_size >= 0xC && packet->signature == PacketHeader::MAGIC && packet->packetTy == MyPacket_6_sessionDesc::ID) {
            if ( v4_size < sizeof(MyPacket_6_sessionDesc) ) {
                _log("\tBullfrogNET:got a session packet from a Host, but its corrupt\n");
            } else {
                handleSessionPacket((MyPacket_6_sessionDesc *) packet, sysTime);
            }
        }
        LeaveCriticalSection(&this->dataLock);
    }
    net::operator_delete(packet);
    _log("\tBullfrogNET::Ending EnumerateSessions Thread\n");
    EnterCriticalSection(&this->dataLock);
    this->f59F_enumerateSessions_hThread = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&this->dataLock);
}

int BullfrogNET::EnumerateSessions2(
        DWORD *a2_pTimeout, MySocket *a3_lobbySock_dst, int a4_callback, char *hostname,
        __int16 a6_flags, void *a7_arg) {
    int ipv4Be = htonl(0xFFFFFFFF);
    if ( (this->f58F_flags & 8) != 0 ) return TRUE;
    this->f58F_flags = 1;

    this->f57B_enumerateSessions_sock = {0, NULL, 0};

    if ( this->f56d_pAddress->connect(&this->f57B_enumerateSessions_sock, this->f6B3_myaddr.f14_ipv4) )
        return FALSE;
    if ( hostname ) {
        if ( strlen(hostname) != 0 ) {
            ipv4Be = inet_addr(hostname);
            if ( ipv4Be == -1 ) {
                ipv4Be = this->f56d_pAddress->resolve(hostname);
                if ( ipv4Be == -1 ) {
                    _log("\tBullfrogNET:: EnumerateSessions Error:-INVALID IP ADDRESS %s \n", hostname);
                    MySocket_close(&this->f57B_enumerateSessions_sock);
                    return FALSE;
                }
            }
        }
        if ( *a2_pTimeout == 0) {  // auto calc timeout
            if ( (a6_flags & 0x400) != 0 ) {
                if ( ipv4Be == htonl(0xFFFFFFFF) ) {
                    *a2_pTimeout = 30000;
                } else {
                    *a2_pTimeout = 120000;
                    this->f58F_flags = 2;
                }
            } else {
                if ( ipv4Be == htonl(0xFFFFFFFF) ) {
                    *a2_pTimeout = 10000;
                } else {
                    *a2_pTimeout = 20000;
                    this->f58F_flags = 2;
                }
            }
        }
        if ( (a6_flags & 0x400) != 0 ) {
            this->f58F_flags |= 4;
        }
    }
    if ( (a6_flags & 2) != 0 ) {
        this->f58F_flags |= 8;
    }
    HANDLE hThread = (HANDLE) _beginthread([](void *arg) {
        ((BullfrogNET *) arg)->EnumerateSessions_proc();
    }, 0, this);
    this->f59F_enumerateSessions_hThread = hThread;
    if (hThread == INVALID_HANDLE_VALUE ) {
        MySocket_close(&this->f57B_enumerateSessions_sock);
        return FALSE;
    }
    a3_lobbySock_dst->ipv4 = ipv4Be;
    MyDPlayCompoundAddress *f30_dPlayAddr = this->f30_dPlayAddr;
    if ( !f30_dPlayAddr->f12_addr.f8_port )
        f30_dPlayAddr->f12_addr.f8_port = 7575;
    a3_lobbySock_dst->portBe = htons(this->f30_dPlayAddr->f12_addr.f8_port);
    return TRUE;
}

int BullfrogNET::EnumerateSessions_impl(
        DWORD a2_timeout, EnumerateSessionsCallback a3_callback,
        int a4_flags, void *a5_arg, char *f0_pAddr) {

    if ( a4_flags == 4 ) {
        _log("\tBullfrogNET::EnumerateSessions Stop. Destroying List\n");
        this->waitResetSessions(1);
        return 2;
    }

    if ( (this->f58F_flags & 8) == 0 ) {
        timeGetSystemTime(&g_EnumerateSessions_sysTime_0, 0xCu);
        timeGetSystemTime(&g_EnumerateSessions_sysTime_1, 0xCu);
    }

    if ( !this->EnumerateSessions2(
            &a2_timeout,
            &g_EnumerateSessions_lobbySock_dst,
            (int)a3_callback,
            f0_pAddr,
            a4_flags,
            a5_arg
    )) return 0x20;

    g_EnumerateSessions_sysTime_0.wType = 1;
    struct mmtime_tag sysTime;
    sysTime.wType = 1;
    g_EnumerateSessions_sysTime_1.wType = 1;
    timeGetSystemTime(&sysTime, 0xCu);
    MyPacket_5_SessionRequest lobbyPacket;
    lobbyPacket.f0_hdr.signature = PacketHeader::MAGIC;
    lobbyPacket.f0_hdr.packetTy = MyPacket_5_SessionRequest::ID;

    lobbyPacket.fC_guidApplication = this->f44_guidApplication;

    struct mmtime_tag v22_sysTime;
    char f58F_flags = this->f58F_flags;
    if ( (f58F_flags & 8) != 0
         || (MySocket_send(&this->f57B_enumerateSessions_sock, &g_EnumerateSessions_lobbySock_dst, &lobbyPacket, 0x1C),
            (this->f58F_flags & 8) != 0) ) {
        v22_sysTime.wType = 1;
        timeGetSystemTime(&v22_sysTime, 0xCu);
        if (v22_sysTime.u.ms - g_EnumerateSessions_sysTime_1.u.ms >= 500 ) {
            MySocket_send(&this->f57B_enumerateSessions_sock, &g_EnumerateSessions_lobbySock_dst, &lobbyPacket, 0x1C);
            g_EnumerateSessions_sysTime_1.wType = 1;
            timeGetSystemTime(&g_EnumerateSessions_sysTime_1, 0xCu);
        }
        EnterCriticalSection(&this->dataLock);
        ListEntry_SessionDesc *sessionList = this->f593_sessionList;
        if (sessionList && a3_callback ) {
            ListEntry_SessionDesc *fA8_next = this->f593_sessionList;
            v22_sysTime.wType = 1;
            timeGetSystemTime(&v22_sysTime, 0xCu);
            do {
                int fA4_timeMs = sessionList->fA4_timeMs;
                if ( v22_sysTime.u.ms - fA4_timeMs < 8000 ) {
                    fA8_next = sessionList;
                    sessionList = sessionList->fA8_next;
                } else {
                    _log("OUT OF DATE SESSION:-REMOVING L%d E%d\n", fA4_timeMs, v22_sysTime.u.ms);
                    if (sessionList == this->f593_sessionList ) {
                        fA8_next = sessionList->fA8_next;
                        this->f593_sessionList = fA8_next;
                        net::_free(sessionList);
                        sessionList = fA8_next;
                    } else {
                        fA8_next->fA8_next = sessionList->fA8_next;
                        net::_free(sessionList);
                        sessionList = fA8_next->fA8_next;
                    }
                }
            } while ( sessionList );
            for (ListEntry_SessionDesc *i_sessionDesc = this->f593_sessionList;
                 i_sessionDesc; i_sessionDesc = i_sessionDesc->fA8_next ) {
                a3_callback(&i_sessionDesc->f0_desc, a5_arg);
            }
        }
        LeaveCriticalSection(&this->dataLock);
    } else {
        while (sysTime.u.ms - g_EnumerateSessions_sysTime_0.u.ms < a2_timeout ) {
            sysTime.wType = 1;
            timeGetSystemTime(&sysTime, 0xCu);
            v22_sysTime.wType = 1;
            timeGetSystemTime(&v22_sysTime, 0xCu);
            if ( (this->f58F_flags & 2) != 0 ) {
                EnterCriticalSection(&this->dataLock);
                BOOL hasSessionList = this->f593_sessionList != NULL;
                LeaveCriticalSection(&this->dataLock);
                if ( hasSessionList )
                    break;
            }
            if (v22_sysTime.u.ms - g_EnumerateSessions_sysTime_1.u.ms >= 1000 ) {
                MySocket_send(&this->f57B_enumerateSessions_sock, &g_EnumerateSessions_lobbySock_dst, &lobbyPacket, 0x1C);
                g_EnumerateSessions_sysTime_1.wType = 1;
                timeGetSystemTime(&g_EnumerateSessions_sysTime_1, 0xCu);
            }
        }
        this->waitResetSessions(0);
        ListEntry_SessionDesc *v14_cur = this->f593_sessionList;
        if ( v14_cur ) {
            EnumerateSessionsCallback v15_callback = a3_callback;
            if ( a3_callback ) {
                do {
                    v15_callback(&v14_cur->f0_desc, a5_arg);
                    v14_cur = v14_cur->fA8_next;
                } while ( v14_cur );
            }
        }
        this->clearSessionList();
    }
    if ( (a4_flags & 4) == 0 )
        return 2;
    _log("\tBullfrogNET::EnumerateSessions Destroying List\n");
    this->waitResetSessions(1);
    return 2;
}
int BullfrogNET::EnumerateSessions(
        DWORD a2_timeout, EnumerateSessionsCallback a3_callback,
        int a4_flags, void *a5_arg) {
    if ( !this->f20_isServiceProviderInitialized ) {
        _log("\tBullfrogNET::EnumerateSession Error:-Service Provider Not Initialised\n");
        return 0x20;
    }
    if (this->f226_curPlayer.isConnectedToSession()) {
        _log("\tBullfrogNET::EnumerateSessions Error:-Cannot Enumerate Sessions when connected to a session\n");
        return 0x20;
    }
    MyDPlayCompoundAddress *f30_dPlayAddr = this->f30_dPlayAddr;
    if ( !f30_dPlayAddr ) {
        _log("\tBullfrogNET::EnumerateSessions Error:-Connection Not Setup (hint:Use SetupConnection)\n");
        return 0x20;
    }
    char *f0_pAddr = (char *)f30_dPlayAddr->f12_addr.f0_pAddr;
    if ( (a4_flags & 2) == 0 ) {
        if ( (a4_flags & 4) != 0 ) {
            _log("\tBullfrogNET::EnumerateSessions:- Application Stopping Async session looking\n");
            if ( (this->f58F_flags & 0x20) != 0 ) {
                this->getHostByname_destroy();
                this->f58F_flags = 0;
            }
        }
        return EnumerateSessions_impl(a2_timeout, a3_callback, a4_flags, a5_arg, f0_pAddr);
    }

    if ( (this->f58F_flags & 8) != 0 ) {
        return EnumerateSessions_impl(a2_timeout, a3_callback, a4_flags, a5_arg, f0_pAddr);
    }

    if ( (this->f58F_flags & 0x20) == 0 ) {
        if ( f0_pAddr && strlen(f0_pAddr) && inet_addr(f0_pAddr) == -1 ) {
            if ( this->getHostByName_async(f0_pAddr) ) {
                _log("\tBullfrogNET::EnumerateSessions:-Looking up Host %s\n", f0_pAddr);
                this->f58F_flags |= 0x20u;
                timeGetSystemTime(&g_EnumerateSessions_sysTime_0, 0xCu);
                return 0x20000;
            } else {
                _log("\tBullfrogNET::EnumerateSessions:-Failed To Create Host Lookup Window\n");
                return 0x20;
            }
        }
        return EnumerateSessions_impl(a2_timeout, a3_callback, a4_flags, a5_arg, f0_pAddr);
    }

    if ( this->getHostByName_collectResults() ) {
        this->f58F_flags = 0;
        this->getHostByname_destroy();
        return EnumerateSessions_impl(a2_timeout, a3_callback, a4_flags, a5_arg, f0_pAddr);
    }

    struct mmtime_tag sysTime;
    sysTime.wType = 1;
    timeGetSystemTime(&sysTime, 0xCu);
    if (sysTime.u.ms - g_EnumerateSessions_sysTime_0.u.ms < 10005 )
        return 0x20000;
    _log("\tBullfrogNET::EnumerateSessions:-ERROR UNKNOWN HOST\n");
    this->getHostByname_destroy();
    this->f58F_flags = 0;
    return 0x40000;
}

BOOL BullfrogNET::getHostByName_collectResults() {
    if ( !g_getHostByName_async_isComplete ) return FALSE;
    HOSTENT &hostent = *(HOSTENT *) g_getHostByName_async_hostent;
    in_addr **addrList = (struct in_addr **) hostent.h_addr_list;
    strcpy(this->f5A7_dst_addrStr_by_getHostByName, inet_ntoa(**addrList));
    return TRUE;
}

int BullfrogNET::EnumPlayers(
        GUID *a2_guidInstance, MyPlayerEnumCb a3_callback,
        int a4_ignored, void *a5_arg) {
    if ( this->f20_isServiceProviderInitialized ) return 2;
    return 0x20;
}

void BullfrogNET::EnableNewPlayers(int a2_enabled) {
    if ( a2_enabled ) {
        this->f186_sessionDesc.flags &= ~0x10;
    } else {
        this->f186_sessionDesc.flags |= 0x10;
    }
}

PacketHeader *BullfrogNET::_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) {
    uint16_t f6_playerListIdx_m1_m2 = a2_packet->playerListIdx_m1_m2;
    if (f6_playerListIdx_m1_m2 == this->f226_curPlayer.playersSlot
         || f6_playerListIdx_m1_m2 == net_HostPlayer && this->f226_curPlayer.isHost() ) {
        int messageSize = a2_packet->f8_messageSize;
        this->messageHandler(
                a2_packet->playersSlot,
                (char *)&a2_packet[1], messageSize,
                a3_handlerTy, this->f4_arg
        );
        *a4_outSize = messageSize;
        return a2_packet;
    }
    if ( f6_playerListIdx_m1_m2 == net_AllPlayers) {
        int messageSize = a2_packet->f8_messageSize;
        this->messageHandler(
                a2_packet->playersSlot,
                (char *)&a2_packet[1], messageSize,
                a3_handlerTy, this->f4_arg
        );
        *a4_outSize = messageSize;
        if (this->f226_curPlayer.isHost()) {
            EnterCriticalSection(&this->dataLock);
            this->SendMessage(net_AllPlayers, a2_packet, sizeof(PacketHeader) + a2_packet->f8_messageSize, 0);
            LeaveCriticalSection(&this->dataLock);
        }
        return a2_packet;
    }
    if ( f6_playerListIdx_m1_m2 == net_AllPlayers2 ) {
        int messageSize = a2_packet->f8_messageSize;
        this->messageHandler(
                a2_packet->playersSlot,
                (char *)&a2_packet[1], messageSize,
                a3_handlerTy, this->f4_arg
        );
        *a4_outSize = messageSize;
        if (this->f226_curPlayer.isHost()) {
            EnterCriticalSection(&this->dataLock);
            this->SendMessage(net_AllPlayers, a2_packet, sizeof(PacketHeader) + a2_packet->f8_messageSize, 0);
            LeaveCriticalSection(&this->dataLock);
        }
        return a2_packet;
    }
    if (this->f226_curPlayer.isHost()) {
        EnterCriticalSection(&this->dataLock);
        for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
            MyPlayerDesc *cur = &this->f24_playerList[i];
            if (cur->f35_slotNo != a2_packet->playerListIdx_m1_m2) continue;
            _log("3\n");
            this->SendMessage(cur->f20_playerId_slot, a2_packet, sizeof(PacketHeader) + a2_packet->f8_messageSize, 0);
            break;
        }
        LeaveCriticalSection(&this->dataLock);
    }
    return NULL;
}

BOOL BullfrogNET::SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) {
    if (!this->f226_curPlayer.isHost()) {
        MySocket a2_to;
        a2_to.ipv4 = this->f54_host_ipv4;
        a2_to.portBe = this->f58_host_portBe;
        MySocket_send(&this->f571_joinSession_sock, &a2_to, a3_buf, a4_size);
        return TRUE;
    }
    PlayerId v7_playerId_slot = { .value = a2_playerId_slot };
    if (a2_playerId_slot == net_AllPlayers) {
        for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
            MyPlayerDesc *cur = &this->f24_playerList[i];
            if (cur->f20_playerId_slot == this->f226_curPlayer.playerId) continue;
            MySocket dstSock = {cur->f36_subDesc.f4_portBe, NULL, cur->f36_subDesc.f0_ipv4};
            MySocket_send(&this->f571_joinSession_sock, &dstSock, a3_buf, a4_size);
        }
        return TRUE;
    }
    if (a2_playerId_slot == net_HostPlayer) {
        v7_playerId_slot = this->f28_host_playerId;
    }
    unsigned int playerListIdx = this->__getHiWord(v7_playerId_slot);
    if (playerListIdx >= this->f186_sessionDesc.totalMaxPlayers)
        return FALSE;
    MyPlayerDesc *v11_playerDesc = &this->f24_playerList[playerListIdx];
    if (!v11_playerDesc->isJoined() || v11_playerDesc->f20_playerId_slot != v7_playerId_slot)
        return FALSE;
    MySocket dstSock = {v11_playerDesc->f36_subDesc.f4_portBe, NULL, v11_playerDesc->f36_subDesc.f0_ipv4};
    MySocket_send(&this->f571_joinSession_sock, &dstSock, a3_buf, a4_size);
    return TRUE;
}

int BullfrogNET::SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) {
    if (!this->f226_curPlayer.isConnectedToSession()) return 0;
    MySocket_send(&this->f571_joinSession_sock, a2_dstSock, a3_buf, a4_size);
    return 1;
}

int BullfrogNET::isCriticalError() {
    switch ( GetLastError() ) {
        case WSAEINTR: _log("\tBullfrogNET:: The (blocking) call was canceled using WSACancelBlockingCall.\n"); return 1;
        case WSAEFAULT: _log("\tBullfrogNET:: The fromlen argument was invalid: the from buffer was too small to accommodate the peer address.\n"); return 1;
        case WSAEINVAL: _log("\tBullfrogNET:: A blocking Windows Sockets operation is in progress.\n"); return 1;
        case WSAEWOULDBLOCK: _log("\tBullfrogNET:: The socket is marked as nonblocking and the recvfrom operation would block.\n");
            return 0;
        case WSAENOTSOCK: _log("\tBullfrogNET:: The descriptor is not a socket.\n"); return 1;
        case WSAEMSGSIZE: _log("\tBullfrogNET:: The datagram was too large to fit into the specified buffer and was truncated.\n");
            return 0;
        case WSAEOPNOTSUPP: _log("\tBullfrogNET:: MSG_OOB was specified, but the socket is not of type SOCK_STREAM.\n"); return 1;
        case WSAENETDOWN: _log("\tBullfrogNET:: The Windows Sockets implementation has detected that the network subsystem has failed.\n"); return 1;
        case WSAECONNABORTED: _log("\tBullfrogNET:: The virtual circuit was aborted due to timeout or other failure.\n"); return 1;
        case WSAECONNRESET: _log("\tBullfrogNET:: The virtual circuit was reset by the remote side.\n"); return 1;
        case WSAENOTCONN: _log("\tBullfrogNET:: The socket is not connected (SOCK_STREAM only).\n"); return 1;
        case WSAESHUTDOWN: _log("\tBullfrogNET:: The socket has been shut down; it is not possible to recvfrom on a socket after shutdown has been invoked with how set to 0 or 2.\n"); return 1;
        case WSANOTINITIALISED: _log("\tBullfrogNET:: A successful WSAStartup must occur before using this function.\n"); return 1;
        default: return 1;
    }
}



void BullfrogNET::handlePacket_5_SessionRequest(
        MySocket *a2_to, MyPacket_5_SessionRequest *a3_packet, unsigned int a4_packetSize) {
    if (!this->f226_curPlayer.isConnectedToSession()) return;
    _log("\tBullfrogNET:Client Querying My Session\n");
    if ( a4_packetSize < sizeof(MyPacket_5_SessionRequest) ) {
        _log("\tBullfrogNET:got a query sessions, packet from client, but its corrupt\n");
        return;
    }
    if (a3_packet->fC_guidApplication != this->f44_guidApplication) return;
    MyPacket_6_sessionDesc *packet = (MyPacket_6_sessionDesc *) net::_malloc(sizeof(MyPacket_6_sessionDesc));
    if (!packet) return;
    packet->f0_hdr.signature = PacketHeader::MAGIC;
    packet->f0_hdr.packetTy = MyPacket_6_sessionDesc::ID;
    packet->fC_desc = this->f186_sessionDesc;
    patch::multi_interface_fix::replaceConnectAddress(packet->fC_desc.sock.ipv4, *a2_to);
    MySocket_send(&this->f571_joinSession_sock, a2_to, packet, sizeof(MyPacket_6_sessionDesc));
    net::_free(packet);
}


void BullfrogNET::handlePacket_7_JoinPlayer(MyPacket_7_Join *a2_joinPacket, MySocket *a2_to) {
    if (!this->f24_playerList) return;
    MyMessage_1_AddedPlayer v24_message;
    MyPlayerSubDesc *foundSubDesc = NULL;
    MyPlayerDesc *foundDesc = NULL;
    int v16_alreadyInSession = 0;
    int v18_sendPlayerAdded = 0;
    int v20_sendPlayerList = 0;
    int v21_handleMessage = 0;
    uint16_t v22_slot = 0;
    EnterCriticalSection(&this->dataLock);
    for (int i = 0; i < this->f186_sessionDesc.totalMaxPlayers; ++i) {
        MyPlayerDesc *curDesc = &this->f24_playerList[i];
        if (!curDesc->isJoined()) continue;
        if (curDesc->f20_playerId_slot == this->f226_curPlayer.playerId) continue;
        foundSubDesc = &curDesc->f36_subDesc;
        if (a2_joinPacket->f30_guidPlayer != curDesc->f36_subDesc.f6_guidPlayer) continue;
        _log("PLAYER IS ALREADY IN SESSION\n");
        foundDesc = curDesc;
        v16_alreadyInSession = 1;
        v18_sendPlayerAdded = 1;
        break;
    }
    int f3C_flags = this->f186_sessionDesc.flags;
    if ( (f3C_flags & 0x10) == 0 && !v16_alreadyInSession ) {
        if ( (f3C_flags & 0x200) != 0 && wcscmp(this->f41F_password, a2_joinPacket->f60_password) ) {
            _log("\tBullNET::Cannot add client incorrect password given\n");
            return;
        }
        for (int v8_slotIdx = 0; v8_slotIdx < this->f186_sessionDesc.totalMaxPlayers; ++v8_slotIdx) {
            MyPlayerDesc *curDesc = &this->f24_playerList[v8_slotIdx];
            if(curDesc->isJoined()) continue;
            int v17_slotNo = v8_slotIdx;
            PlayerId v10_playerId_slot;
            v10_playerId_slot.slotIdx = v8_slotIdx;
            v10_playerId_slot.playerIdx = this->f569_last_playerId_slot.playerIdx + 1;
            this->f569_last_playerId_slot = v10_playerId_slot;
            _log(
                    "ADDING PLAYER %x %d, SLOT NO %d \n",
                    v10_playerId_slot,
                    v10_playerId_slot,
                    HIWORD(*(unsigned int *)&v10_playerId_slot));
            wcscpy(curDesc->f0_playername, a2_joinPacket->f40_playerName);
            curDesc->flags &= 0xFu;
            curDesc->f20_playerId_slot = this->f569_last_playerId_slot;
            curDesc->f35_slotNo = v17_slotNo;
            curDesc->f2C_packet_D_Guaranteed_sendScheduled_count = 0;
            curDesc->f30_receivedScheduled_count = 0;
            foundSubDesc = &curDesc->f36_subDesc;
            curDesc->f36_subDesc.f0_ipv4 = a2_to->ipv4;
            curDesc->f36_subDesc.f4_portBe = a2_to->portBe;
            curDesc->f36_subDesc.f6_guidPlayer = a2_joinPacket->f30_guidPlayer;
            ++this->f186_sessionDesc.currentPlayers;
//                    NetworkServiceProvider_schedulePlayersChangePacket
            this->schedulePlayersChangePacket(
                    MyPacket_1_Create::ID,
                    this->f569_last_playerId_slot,
                    v17_slotNo,
                    a2_joinPacket->f40_playerName,
                    a2_joinPacket->fC_flags);
            PlayerId f20_playerId_slot = curDesc->f20_playerId_slot;
            curDesc->flags = curDesc->flags & 0xF0 | 1;
            _log("ADDED NEW PLAYER ID %d\n", f20_playerId_slot);
            v18_sendPlayerAdded = 1;
            v20_sendPlayerList = 1;
            v22_slot = (unsigned __int8)v17_slotNo;
            v24_message.f0_message = 1;
            v24_message.f5_slotNo = curDesc->f35_slotNo;
            v24_message.f26_playerId_slot = curDesc->f20_playerId_slot;
            MyPlayerDesc *v15 = &this->f24_playerList[v17_slotNo];
            wcscpy(v24_message.f6_playerName, v15->f0_playername);
            foundDesc = curDesc;
            v21_handleMessage = 1;
            break;
        }
    }
    if ( v18_sendPlayerAdded ) {
        MyPacket_8_PlayerAdded playerAddedPacket;
        playerAddedPacket.f0_hdr.signature = PacketHeader::MAGIC;
        playerAddedPacket.f0_hdr.packetTy = MyPacket_8_PlayerAdded::ID;
        playerAddedPacket.f10_guidApplication = this->f44_guidApplication;
        playerAddedPacket.f20_guidInstance = this->f186_sessionDesc.guidInstance;
        playerAddedPacket.f30_guidPlayer = foundSubDesc->f6_guidPlayer;
        int f28_currentPlayers = this->f186_sessionDesc.currentPlayers;
        playerAddedPacket.f40_playerId = foundDesc->f20_playerId_slot;
        int v13_totalMaxPlayers = this->f186_sessionDesc.totalMaxPlayers;
        playerAddedPacket.f44_hostPlayerId = this->f226_curPlayer.playerId;
        playerAddedPacket.f4C_currentPlayers = f28_currentPlayers;
        playerAddedPacket.f48_totalMaxPlayers = v13_totalMaxPlayers;
        MySocket_send(&this->f571_joinSession_sock, a2_to, &playerAddedPacket, sizeof(MyPacket_8_PlayerAdded));
    }
    if ( v20_sendPlayerList ) {
        this->send_B_PlayerList(v22_slot);
        SetEvent(this->f16A_playerCountChange_hEvent);
    }
    LeaveCriticalSection(&this->dataLock);
    if ( v21_handleMessage )
        this->messageHandler(net_HostPlayer, &v24_message, sizeof(MyMessage_1_AddedPlayer), 1, this->f4_arg);
}

void BullfrogNET::handlePacket_A_DestroyPlayer(MyPacket_A_DestroyPlayer *packet, unsigned int a3_size, MySocket *a2_to) {
    int v14_destroyPlayer = 0;
    if (a3_size < sizeof(MyPacket_A_DestroyPlayer)) return;
    if (packet->f2C_guidApplication != this->f44_guidApplication) return;
    if (packet->f3C_guidInstance != this->f186_sessionDesc.guidInstance) return;
    unsigned int v5_slot = this->__getHiWord(packet->f5C_playerId);
    int v17_handleMessage = 0;
    PlayerId v13_playerId = {0};
    EnterCriticalSection(&this->dataLock);
    PlayerId v9_playerId = {0};
    if (v5_slot < this->f186_sessionDesc.totalMaxPlayers && this->f24_playerList) {
        MyPlayerDesc *v7_payerDesc = &this->f24_playerList[v5_slot];
        if (
                v7_payerDesc->isJoined() &&
                packet->f4C_guidPlayer == v7_payerDesc->f36_subDesc.f6_guidPlayer &&
                v7_payerDesc->f20_playerId_slot == packet->f5C_playerId
        ) {
            v9_playerId = v7_payerDesc->f20_playerId_slot;
            _log("\tBullfrogNET::DESTROYING PLAYER Index %d\n", packet->f5C_playerId);
            v13_playerId = v9_playerId;
            memset(v7_payerDesc, 0, sizeof(MyPlayerDesc));
            --this->f186_sessionDesc.currentPlayers;
            this->f5A_ackPacketCount_perPlayerSlot[v5_slot] = 0;
            v17_handleMessage = 1;
            this->fDA_unused1_perPlayerSlot[v5_slot] = 0;
            v14_destroyPlayer = 1;
            this->releasePacketSendArr_forPlayer(v5_slot);
        }
    }
    LeaveCriticalSection(&this->dataLock);
    if ( v17_handleMessage )
        this->messageHandler(net_HostPlayer, &v13_playerId, sizeof(PlayerId), 2, this->f4_arg);
    EnterCriticalSection(&this->dataLock);

    if (this->f226_curPlayer.isHost()) {
        packet->f0_hdr.packetTy = MyPacket_9_PlayerLeave::ID;
        // content MyPacket_9_PlayerLeave == MyPacket_A_DestroyPlayer
        MySocket_send(&this->f571_joinSession_sock, a2_to, packet, sizeof(MyPacket_9_PlayerLeave));
        if ( v14_destroyPlayer ) {
            this->schedulePlayersChangePacket(MyPacket_9_PlayerLeave::ID, v9_playerId, 0, NULL, 0);
        }
    } else if (
            packet->f4C_guidPlayer == this->f34_guidPlayer &&
            packet->f5C_playerId == this->f226_curPlayer.playerId
            ) {
        _log("\tBullfrogNET::Destroying My player\n");
        this->f226_curPlayer.flags &= ~2;
    }
    LeaveCriticalSection(&this->dataLock);
}

PacketHeader *BullfrogNET::handleLobbyPacket(PacketHeader *packet, int size, MySocket &sockSrc) {
    switch (packet->packetTy) {
        case MyPacket_3_Data::ID:
        case MyPacket_D_Guaranteed::ID:
        case MyPacket_10_GuaranteedProgress::ID:
            return this->f565_recvdData;
        case MyPacket_4_ChatMessage::ID:
            return this->f565_recvdData;
        case MyPacket_5_SessionRequest::ID:  // query sessions
            EnterCriticalSection(&this->dataLock);
            this->handlePacket_5_SessionRequest(&sockSrc, (MyPacket_5_SessionRequest *) packet, size);
            LeaveCriticalSection(&this->dataLock);
            break;
        case MyPacket_7_Join::ID: {
            auto *joinPacket = (MyPacket_7_Join *) packet;
            if (size >= sizeof(MyPacket_7_Join)
                && this->f226_curPlayer.isConnectedToSession()
                && joinPacket->f10_guidApplication == this->f44_guidApplication
                && joinPacket->f20_guidInstance == this->f186_sessionDesc.guidInstance
            ) {
                _log("\tBullfrogNET:got a request to join this session\n");
                this->handlePacket_7_JoinPlayer((MyPacket_7_Join *) packet, &sockSrc);
            }
        }
            break;
        case MyPacket_A_DestroyPlayer::ID:
            this->handlePacket_A_DestroyPlayer((MyPacket_A_DestroyPlayer *) packet, size, &sockSrc);
            break;
        case MyPacket_C_HandledPackets::ID:
            if (size >= sizeof(MyPacket_C_HandledPackets))
                this->handlePacket_C((MyPacket_C_HandledPackets *) this->f565_recvdData);
            break;
        default: break;
    }
    return NULL;
}
PacketHeader *BullfrogNET::handleNotLobbyPacket(PacketHeader *v7_recvdData, int v6_size, MySocket &sockSrc) {
    switch (v7_recvdData->packetTy) {
        case MyPacket_3_Data::ID:
        case MyPacket_D_Guaranteed::ID:
        case MyPacket_10_GuaranteedProgress::ID:
            if (v7_recvdData) return v7_recvdData;
            break;
        case MyPacket_4_ChatMessage::ID:
            if (v7_recvdData) return v7_recvdData;
            break;
        case MyPacket_F_MigrateHost::ID: {
            auto *migrateHostPacket = (MyPacket_F_MigrateHost *) v7_recvdData;
            if (!this->f226_curPlayer.isHost()
                && v6_size >= sizeof(MyPacket_F_MigrateHost)
                && migrateHostPacket->f34_guidApplication == this->f44_guidApplication
                && migrateHostPacket->f44_guidInstance == this->f186_sessionDesc.guidInstance
                && migrateHostPacket->f74_playerId_slot == this->f226_curPlayer.playerId) {
                _log("IAM THE NEW HOST\n");
                int isPlayerFound = 0;
                PlayerId f20_playerId_slot = {0};
                EnterCriticalSection(&this->dataLock);
                MyPlayerDesc *playerList = this->f24_playerList;
                if (playerList < &playerList[this->f186_sessionDesc.totalMaxPlayers]) {
                    do {
                        if (playerList->isJoined()) {
                            if (playerList->f20_playerId_slot == migrateHostPacket->f18_curPlayerId) {
                                isPlayerFound = 1;
                                this->fDA_unused1_perPlayerSlot[playerList->f35_slotNo] = 0;
                                this->f5A_ackPacketCount_perPlayerSlot[playerList->f35_slotNo] = 0;
                                f20_playerId_slot = playerList->f20_playerId_slot;
                                memset(playerList, 0, 0x4Cu);
                                playerList->f36_subDesc.f16__sdUnk1 = 0;
                                playerList->f36_subDesc.f18__sdUnk2 = 0;
                            } else if (playerList->isHost()) {
                                playerList->flags &= 0xFu;
                            }
                        }
                        ++playerList;
                    } while (playerList < &this->f24_playerList[this->f186_sessionDesc.totalMaxPlayers]);
                }
                int f8_playersSlot = this->f226_curPlayer.playersSlot;
                this->f226_curPlayer.flags |= 1u;
                this->f24_playerList[f8_playersSlot].flags = this->f24_playerList[f8_playersSlot].flags & 0xF | 0x10;
                LeaveCriticalSection(&this->dataLock);
                if (isPlayerFound)
                    this->messageHandler(net_HostPlayer, (char *) &f20_playerId_slot, 4, 2, this->f4_arg);
                EnterCriticalSection(&this->dataLock);
                this->f186_sessionDesc.flags = migrateHostPacket->f14_sessionFlags;
                this->f186_sessionDesc.totalMaxPlayers = migrateHostPacket->f1C_totalMaxPlayers;
                this->f186_sessionDesc.currentPlayers = migrateHostPacket->f20_currentPlayers;
                PlayerId playerId_slot = migrateHostPacket->fA3_last_playerId_slot;
                this->f569_last_playerId_slot = playerId_slot;
                _log("IM NEW HOST UNIQUE %x %d, SLOT NO %d \n",
                     playerId_slot, playerId_slot, playerId_slot.slotIdx);
                this->schedulePlayersChangePacket(
                        MyPacket_E_NewHost::ID,
                        this->f226_curPlayer.playerId,
                        this->f226_curPlayer.playersSlot,
                        this->f24_playerList[this->f226_curPlayer.playersSlot].f0_playername,
                        this->f226_curPlayer.flags);
                this->CreateListenServer();
                LeaveCriticalSection(&this->dataLock);
                this->messageHandler(net_HostPlayer, NULL, 0, 0xA, this->f4_arg);
            }
        } break;
        default: break;
    }
    return NULL;
}


PacketHeader *BullfrogNET::ReadSPMessage() {
    if ( !this->f565_recvdData ) {
        PacketHeader *v2_recvdData = (PacketHeader *) net::_malloc(0x1000u);
        this->f565_recvdData = v2_recvdData;
        if (v2_recvdData == NULL) return NULL;
    }

    while (true) {
        if (!this->f226_curPlayer.isHost()) {
            EnterCriticalSection(&this->dataLock);
            bool isSpMessage = this->popReceivedPacketToHandle(this->f565_recvdData);
            PacketHeader *v13_recvdData = this->f565_recvdData;
            LeaveCriticalSection(&this->dataLock);
            if (isSpMessage) return v13_recvdData;
        }
        SOCKET v3_socket = this->f571_joinSession_sock.socket;
        if (v3_socket == -1) break;
        fd_set exceptfds;
        FD_ZERO(&exceptfds);
        FD_SET(v3_socket, &exceptfds);
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(v3_socket, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        int status = ::select(-1, &readfds, NULL, &exceptfds, &timeout);
        EnterCriticalSection(&this->dataLock);
        this->sendPacket_6_SessionDesc();
        LeaveCriticalSection(&this->dataLock);
        if ( status == 0 ) continue;
        if ( status == -1 ) {
            if (this->isCriticalError()) break;
            continue;
        }
        if ( status < 0 ) continue;
        if ( FD_ISSET(this->f571_joinSession_sock.socket, &exceptfds) ) {
            _log("GOT AN EXCEPTION SOCKET\n");
            break;
        }
        if (!FD_ISSET(this->f571_joinSession_sock.socket, &readfds)) continue;
        MySocket sockSrc;
        int v5_size = MySocket_recv(this->f565_recvdData, 0x1000, &this->f571_joinSession_sock, &sockSrc);
        if ( v5_size == -1 ) {
            if ( this->isCriticalError() ) break;
            continue;
        }
        if (v5_size == 0) break;
        if (v5_size < sizeof(PacketHeader) || this->f565_recvdData->signature != PacketHeader::MAGIC) continue;
        if (this->f226_curPlayer.isHost()) {
            if(this->handleLobbyPacket(this->f565_recvdData, v5_size, sockSrc)) {
                patch::log::spmsg("sp[lb] return %X", this->f565_recvdData->packetTy);
                return this->f565_recvdData;
            }
            patch::log::spmsg("sp[lb] handled %X", this->f565_recvdData->packetTy);
            continue;
        }

        EnterCriticalSection(&this->dataLock);
        int isPacketHandled = this->handlePacket_1_2_9_B_E(this->f565_recvdData, v5_size, &sockSrc);
        LeaveCriticalSection(&this->dataLock);
        if (isPacketHandled) {
            patch::log::spmsg("sp[nl] handled 129BE %X", this->f565_recvdData->packetTy);
            continue;
        }

        if(this->handleNotLobbyPacket(this->f565_recvdData, v5_size, sockSrc)) {
            patch::log::spmsg("sp[nl] return %X", this->f565_recvdData->packetTy);
            return this->f565_recvdData;
        }
        patch::log::spmsg("sp[nl] handled %X", this->f565_recvdData->packetTy);
    }
    return NULL;
}
void BullfrogNET::ListenThread_proc() {
    _log("\tBullfrogNET::Starting ListenThread Thread\n");

    PacketHeader *packet = (PacketHeader *) net::operator_new(1024);
    if ( packet ) {
        int isCriticalError = 0;
        while (!isCriticalError) {
            fd_set readfds
            FD_ZERO(&readfds);
            FD_SET(this->f585_listenThread_sock.socket, &readfds);

            fd_set exceptfds;
            FD_ZERO(&exceptfds);
            FD_SET(this->f585_listenThread_sock.socket, &exceptfds);

            struct timeval timeout;
            timeout.tv_sec = 10;
            timeout.tv_usec = 0;

            int v2_selStat = select(-1, &readfds, NULL, &exceptfds, &timeout);
            if ( v2_selStat <= 0 ) {
                if ( !v2_selStat ) {
                    _log("TIMEOUT DUDEnnnn\n");
                    continue;
                }
                isCriticalError = BullfrogNET::isCriticalError();
                continue;
            }
            if (!FD_ISSET(this->f585_listenThread_sock.socket, &readfds)) continue;
            MySocket a2_to;
            unsigned int v3_status = MySocket_recv(packet, 1024, &this->f585_listenThread_sock, &a2_to);
            if ( v3_status == -1 ) {
                isCriticalError = BullfrogNET::isCriticalError();
                continue;
            }
            if (v3_status == 0) {
                isCriticalError = 1;
                continue;
            }
            if (v3_status < sizeof(PacketHeader) || packet->signature != PacketHeader::MAGIC) continue;
            if (!this->f226_curPlayer.isHost()) continue;

            if (packet->packetTy == MyPacket_5_SessionRequest::ID) {
                auto *requestPacket = (MyPacket_5_SessionRequest *) packet;
                EnterCriticalSection(&this->dataLock);
                _log("\tBullfrogNET:Client Querying My Session\n");
                if (v3_status < sizeof(MyPacket_5_SessionRequest)) {
                    _log("\tBullfrogNET:got a query sessions, packet from client, but its corrupt\n");
                } else {
                    if (requestPacket->fC_guidApplication == this->f44_guidApplication) {
                        MyPacket_6_sessionDesc *v5_resp = (MyPacket_6_sessionDesc *) net::_malloc(0xB0u);
                        if (v5_resp) {
                            v5_resp->f0_hdr.signature = PacketHeader::MAGIC;
                            v5_resp->f0_hdr.packetTy = MyPacket_6_sessionDesc::ID;
                            v5_resp->fC_desc = this->f186_sessionDesc;
                            patch::multi_interface_fix::replaceConnectAddress(v5_resp->fC_desc.sock.ipv4, a2_to);
                            MySocket_send(&this->f585_listenThread_sock, &a2_to, v5_resp, sizeof(MyPacket_6_sessionDesc));
                            net::_free(v5_resp);
                        }
                    }
                }
                LeaveCriticalSection(&this->dataLock);
                continue;
            } else if (packet->packetTy == MyPacket_7_Join::ID) {
                auto *joinPacket = (MyPacket_7_Join *) packet;
                int v9_validJoin = 0;
                EnterCriticalSection(&this->dataLock);
                if (v3_status >= sizeof(MyPacket_7_Join)
                    && joinPacket->f10_guidApplication == this->f44_guidApplication
                    && joinPacket->f20_guidInstance == this->f186_sessionDesc.guidInstance) {
                    _log("\tBullfrogNET:got a request to join this session\n");
                    v9_validJoin = 1;
                }
                LeaveCriticalSection(&this->dataLock);
                if (v9_validJoin)
                    this->handlePacket_7_JoinPlayer(joinPacket, &a2_to);
            }
        }
    }
    net::operator_delete(packet);
    _log("\tBullfrogNET::Ending ListenThread Thread\n");
    EnterCriticalSection(&this->dataLock);
    this->f597_listenThread_hThread = INVALID_HANDLE_VALUE;
    LeaveCriticalSection(&this->dataLock);
}

void BullfrogNET::CreateListenServer() {
    this->f585_listenThread_sock = {0, NULL, 0};

    __int16 f8_port = this->f30_dPlayAddr->f12_addr.f8_port;
    int f14_ipv4 = this->f6B3_myaddr.f14_ipv4;
    DnsResolver *f56d_pAddress = this->f56d_pAddress;
    MySocket *p_f585_listenThread_sock = &this->f585_listenThread_sock;
    p_f585_listenThread_sock->portBe = f8_port;
    if ( f56d_pAddress->connect(p_f585_listenThread_sock, f14_ipv4) ) {
        _log("\tBullfrogNET::CreateListenServer:-ERROR COULDN'T CREATE LISTEN SOCKET\n");
        return;
    }
    HANDLE v5_hThread = (HANDLE) _beginthread([](void *arg) {
        ((BullfrogNET *) arg)->ListenThread_proc();
    }, 0, this);
    this->f597_listenThread_hThread = v5_hThread;
    if ( v5_hThread == INVALID_HANDLE_VALUE ) {
        MySocket_close(p_f585_listenThread_sock);
        _log("\tBullfrogNET::CreateListenServer:-ERROR COULDN'T CREATE LISTEN THREAD\n");
    }
}

unsigned int __stdcall getIpv4_fromAddr(char *cp, unsigned int *a2_pIp) {
    unsigned int result = inet_addr(cp);
    *a2_pIp = result;
    return result;
}

void BullfrogNET::sendPacket_6_SessionDesc() {
    if (!this->f45F_getHostByName_isPresent) return;
    this->getHostByName_collectResults();
    if (!this->f226_curPlayer.isHost()) return;
    if (!strlen(this->f5A7_dst_addrStr_by_getHostByName)) return;
    struct mmtime_tag sysTime;
    sysTime.wType = 1;
    timeGetSystemTime(&sysTime, 0xCu);
    if (sysTime.u.ms - this->f6CB_sysTime.u.ms < 5000) return;
    this->f6CB_sysTime.wType = 1;
    timeGetSystemTime(&this->f6CB_sysTime, 0xCu);
    MyPacket_6_sessionDesc *packet = (MyPacket_6_sessionDesc *) net::_malloc(sizeof(MyPacket_6_sessionDesc));
    if (!packet) return;
    unsigned int v4_ipv4;
    getIpv4_fromAddr(this->f5A7_dst_addrStr_by_getHostByName, &v4_ipv4);
    MySocket v5_sock = {htons(this->f563_getHostByName_port), NULL, v4_ipv4};
    packet->f0_hdr.signature = PacketHeader::MAGIC;
    packet->f0_hdr.packetTy = MyPacket_6_sessionDesc::ID;
    packet->fC_desc = this->f186_sessionDesc;
    patch::multi_interface_fix::replaceConnectAddress(packet->fC_desc.sock.ipv4, v5_sock);
    MySocket_send(&this->f571_joinSession_sock, &v5_sock, packet, sizeof(MyPacket_6_sessionDesc));
    net::_free(packet);
}

int BullfrogNET::DestroySession(unsigned int a2_slot) {
    if (!this->f20_isServiceProviderInitialized) {
        _log("\tNetworkServiceProvider::DestroySession Error::ServiceProvider Not Initialised\n");
        return 0x20;
    }
    if (!this->f226_curPlayer.isConnectedToSession()) {
        _log("\tNetworkServiceProvider::DestroySession Error::Not connected to session\n");
        return 0x20;
    }
    if (!this->f226_curPlayer.isHost()) {
        _log("\tNetworkServiceProvider::DestroySession Error::Not host\n");
        return 0x80000;
    }
    return this->destroyPlayer(a2_slot);
}

int BullfrogNET::destroyPlayer(unsigned int a2_slot) {
    PlayerId f20_playerId_slot = {0};
    int v10_updatePlayers = 0;
    int v8_handleMessage = 0;
    PlayerId v9_playerId_slot = {0};
    EnterCriticalSection(&this->dataLock);
    if ( a2_slot < this->f186_sessionDesc.totalMaxPlayers ) {
        MyPlayerDesc *f24_playerList = this->f24_playerList;
        if ( f24_playerList ) {
            MyPlayerDesc *v5_playerDesc = &f24_playerList[a2_slot];
            if (v5_playerDesc->isJoined()) {
                f20_playerId_slot = v5_playerDesc->f20_playerId_slot;
                _log("\tBullfrogNET::DESTROYING PLAYER Index %d\n", f20_playerId_slot);
                v9_playerId_slot = f20_playerId_slot;

                memset(v5_playerDesc, 0, sizeof(MyPlayerDesc));

                --this->f186_sessionDesc.currentPlayers;
                this->f5A_ackPacketCount_perPlayerSlot[a2_slot] = 0;
                v8_handleMessage = 1;
                this->fDA_unused1_perPlayerSlot[a2_slot] = 0;
                v10_updatePlayers = 1;
                this->releasePacketSendArr_forPlayer(a2_slot);
            }
        }
    }
    LeaveCriticalSection(&this->dataLock);
    if ( v8_handleMessage )
        this->messageHandler(net_HostPlayer, &v9_playerId_slot, 4, 2, this->f4_arg);
    EnterCriticalSection(&this->dataLock);
    if ( this->f226_curPlayer.isHost() && v10_updatePlayers )
        this->schedulePlayersChangePacket(MyPacket_9_PlayerLeave::ID, f20_playerId_slot, 0, NULL, 0);
    LeaveCriticalSection(&this->dataLock);
    return 2;
}

int BullfrogNET::getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) {
    if (!this->f20_isServiceProviderInitialized) return 0x20;
    if (!this->f226_curPlayer.isConnectedToSession()) return 0x20;
    if (!a2_pDesc) {
        *a3_pSize = sizeof(MLDPLAY_SESSIONDESC);
        return 2;
    }
    if (*a3_pSize < sizeof(MLDPLAY_SESSIONDESC)) return 0x20;
    EnterCriticalSection(&this->dataLock);
    memcpy(a2_pDesc, &this->f186_sessionDesc, sizeof(MLDPLAY_SESSIONDESC));
    LeaveCriticalSection(&this->dataLock);
    return 2;
}

int BullfrogNET::setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) {
    DWORD v8_size = sizeof(MLDPLAY_SESSIONDESC);
    if ( !this->f20_isServiceProviderInitialized ) return 0x20;
    MLDPLAY_SESSIONDESC v9_desc;
    this->getSessionDesc(&v9_desc, &v8_size);
    v9_desc.totalMaxPlayers = a2_desc->totalMaxPlayers;
    v9_desc.mapNameLen_mapPlayersCount = a2_desc->mapNameLen_mapPlayersCount;
    v9_desc.mapNameHash = a2_desc->mapNameHash;
    v9_desc.fileHashsum = a2_desc->fileHashsum;
    v9_desc.cred_2C = a2_desc->cred_2C;
    EnterCriticalSection(&this->dataLock);
    memcpy(&this->f186_sessionDesc, &v9_desc, v8_size);
    LeaveCriticalSection(&this->dataLock);
    return 2;
}

void BullfrogNET::setNewHost(MyPacket_E_NewHost *a2_packet) {
    this->f28_host_playerId = a2_packet->f74_playerId;
    this->f54_host_ipv4 = a2_packet->f8A_subDesc.f0_ipv4;
    this->f58_host_portBe = a2_packet->f8A_subDesc.f4_portBe;
}


struct EA_MsInit {  // msapi.dll is a library from "Electronic Arts"
  int field_0;
  int *field_4;
  int *field_8;
  int *field_C;
  char field_10[16];
};
static_assert(sizeof(EA_MsInit) == 0x20);


int BullfrogNET::SendMSResults(const char *a2_message) {
    int result = 0x20;
    if (!a2_message) return result;
    if ((this->f186_sessionDesc.flags & 0x400) == 0) return 0x20;

    if (!strlen(this->f673_SendMS_addr)) return 0x20;

    HMODULE msapi_dll = LoadLibraryA("msapi.dll");
    if (!msapi_dll) {
        _log("\tBullfrogNET::SendMSResults:-Error Failed to Load Library MSAPI.DLL\n");
        return 0x20;
    }

    _log("\tBullfrogNET::SendMSResults:-Load Library MSAPI.DLL\n");
    int v12_num1 = 1;
    int v13_num4 = 4;
    EA_MsInit v18_init;
    v18_init.field_0 = 1;
    v18_init.field_4 = &v13_num4;
    v18_init.field_8 = &v12_num1;
    v18_init.field_C = &v12_num1;
    memset(v18_init.field_10, 0, sizeof(v18_init.field_10));
    typedef int (__cdecl *connectMS_type)(char *);
    auto connectMS = (connectMS_type) GetProcAddress(msapi_dll, "connectMS");
    if (!connectMS) {
        _log("\tBullfrogNET::SendMSResults:-Failed to Get Connect Proc address\n");
        FreeLibrary(msapi_dll);
        return 0x20;
    }

    int result_1 = 0x20;
    _log("\tBullfrogNET::SendMSResults:- Attempting to Connect to %s\n", this->f673_SendMS_addr);
    if (connectMS(this->f673_SendMS_addr) == 1) {
        typedef int (__cdecl *initializeMS_type)(int *, EA_MsInit *, int, int);
        auto initializeMS = (initializeMS_type) GetProcAddress(msapi_dll, "initializeMS");
        if (initializeMS) {
            if (initializeMS(&v12_num1, &v18_init, v13_num4, 0x3C) == 1) {
                size_t v16_data_size = strlen(a2_message) + 0x11;
                char *v8_data = (char *) net::_malloc(v16_data_size);
                if (v8_data) {
                    strcpy(v8_data, this->f663_n_addr);
                    strcat(v8_data, a2_message);
                    strcat(v8_data, "\r\n");
                    _log(
                            "\tBullfrogNET::SendMSResults::Attempting to send data size %d from LoginID %s\n",
                            v16_data_size,
                            this->f663_n_addr);
                    typedef int (__cdecl *sendMSresults_type)(DWORD, char *, unsigned int);
                    auto sendMSresults = (sendMSresults_type) GetProcAddress(msapi_dll, "sendMSresults");
                    if (sendMSresults) {
                        if (sendMSresults(0, v8_data, strlen(v8_data) + 1) == 1) {
                            _log("\tBullfrogNET::SendMSResults::Data Sent successfully\n");
                            result_1 = 2;
                        } else {
                            _log("\tBullfrogNET::SendMSResults::Error Sending Data\n");
                        }
                    } else {
                        _log("BullfrogNET::SendMSResults:-Failed to Get sendMSresults Proc Address\n");
                    }
                    net::_free(v8_data);
                }
            }
        } else {
            _log("BullfrogNET::SendMSResults:-Failed to Get initializeMS Proc Address\n");
        }
    }
    typedef void (__cdecl *closeMS_type)();
    auto closeMS = (closeMS_type) GetProcAddress(msapi_dll, "closeMS");
    if (closeMS) {
        closeMS();
    } else {
        _log("BullfrogNET::SendMSResults:-Failed to Get closeMS Proc Address\n");
    }
    FreeLibrary(msapi_dll);
    return result_1;
}

int BullfrogNET::CreateCompoundAddress(
        DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
        MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) {
    if ( !this->f20_isServiceProviderInitialized ) return 0x20;

    if (a4_outAddr == NULL) {
        *a5_outSize = sizeof(MyDPlayCompoundAddress);
        if (a3_elementCount <= 1) {
            size_t v7_size = 2 * wcslen(L"255.255.255.255") + 2 + *a5_outSize;
            *a5_outSize = v7_size;
            return 0x10;
        }
        if (a2_elements[1].guidDataType != BFAID_INet) return 0x20;

        MyAddr *v5_addr = (MyAddr *) a2_elements[1].lpData;
        if (!v5_addr || a2_elements[1].dwDataSize < sizeof(MyAddr)) return 0x10;

        *a5_outSize += (wcslen(v5_addr->f0_pAddr) + 1) * sizeof(wchar_t);
        return 0x10;
    }

    size_t v9_addr_len;
    if (a3_elementCount <= 1) {
        v9_addr_len = wcslen(L"255.255.255.255");
    } else {
        if (a2_elements[1].guidDataType != BFAID_INet) return 0x20;
        MyAddr *lpData = (MyAddr *) a2_elements[1].lpData;
        if (!lpData || a2_elements[1].dwDataSize < sizeof(MyAddr)) return 0x20;
        v9_addr_len = wcslen(lpData->f0_pAddr);
    }
    unsigned int v10_size = (v9_addr_len + 1) * sizeof(wchar_t) + sizeof(MyDPlayCompoundAddress);
    if (*a5_outSize < v10_size) {
        *a5_outSize = v10_size;
        return 0x10;
    }

    memset(a4_outAddr, 0, sizeof(MyDPlayCompoundAddress));
    memcpy(a4_outAddr, "BF", 2);
    a4_outAddr->f2_guid_BFSPGUID_TCPIP = BFSPGUID_TCPIP;
    if (a3_elementCount <= 1) {
        a4_outAddr->f12_addr.f0_pAddr = (wchar_t *) &a4_outAddr[1];
        a4_outAddr->f12_addr.f8_port = 7575;
        a4_outAddr->f12_addr.f4_size = 2 * wcslen(L"255.255.255.255") + 2;
        wcscpy((wchar_t *) &a4_outAddr[1], L"255.255.255.255");
        return 2;
    }
    if (a2_elements[1].guidDataType != BFAID_INet) {
        _log("\tCreateNetworkAddress Warning:-Unknown GuidDataType\n");
        return 0x20;
    }
    MyAddr *v11_addr = (MyAddr *) a2_elements[1].lpData;
    if (!v11_addr || a2_elements[1].dwDataSize < sizeof(MyAddr)) return 0x20;

    a4_outAddr->f12_addr.f0_pAddr = (wchar_t *) &a4_outAddr[1];
    a4_outAddr->f12_addr.f8_port = v11_addr->f8_port;
    a4_outAddr->f12_addr.f4_size = (wcslen((const wchar_t *) &a4_outAddr[1]) + 1) * sizeof(wchar_t);
    wcscpy((wchar_t *)&a4_outAddr[1], v11_addr->f0_pAddr);
    return 2;
}

