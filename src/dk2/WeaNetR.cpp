//
// Created by DiaLight on 09.01.2025.
//

#include "dk2/network/WeaNetR.h"
#include "dk2/network/MyAddr.h"
#include "dk2/network/BfModemAddr.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "weanetr_dll/MLDPlay.h"
#include "weanetr_dll/globals.h"
#include "dk2_memory.h"
#include "tools/hexdump.hpp"
#include "dplobby.h"
#include "dplay.h"
#include "patches/logging.h"
#include "patches/micro_patches.h"
#include "dk2/network/WeanetrPlayerInfo.h"
#include "dk2/network/MySessionCredentials.h"
#include "dk2/network/MLDPLAY_SESSIONDESC.h"
#include "dk2/network/FoundSessionDesc.h"
#include "patches/protocol_dump.h"


int dk2::WeaNetR::filterService(void *a2_service) {
    net::MyLocalService *service = (net::MyLocalService *) a2_service;
    int guidArrCount = service->f10_count;
    if (!guidArrCount) return 0;

    for (int i = 0; i < guidArrCount; ++i) {
        GUID *curGuid = &service->f24_pGuid[i];
        if( *curGuid == DPAID_ComPort ||
            *curGuid == DPAID_Phone ||
            *curGuid == DPAID_PhoneW ||
            *curGuid == DPAID_Modem ||
            *curGuid == DPAID_Modem ||
            *curGuid == net::BFAID_MODEM
                ) break;

        if( *curGuid == DPAID_INet ||
            *curGuid == DPAID_INetW ||
            *curGuid == net::BFAID_INet
                ) {
            this->selectedServiceIdx = this->networkService_count;
            return 0;
        }
    }
    return 1;
}

void __stdcall dk2_MLDPlay_EnumerateServices_callbaack(net::MyLocalService *service, wchar_t *name, GUID *guid, DWORD idx, void *arg) {
    dk2::WeaNetR *handle = (dk2::WeaNetR *) arg;
    if (handle->networkService_count >= 0x10u) return;
    if (handle->filterService(service)) return;
    handle->services[handle->networkService_count++] = service;
}


void dk2_MLDPlay_HandleMessage_callback(int playersSlot, void *msg, int msgSz, int msgTy, void *arg) {
    dk2::WeaNetR *a5_weanetr = (dk2::WeaNetR *) arg;
    if (msg != NULL) {
        patch::log::data("recv ty=%X sz=%X pl=%X  hty=%X", (int) (*(uint8_t *) msg), msgSz, playersSlot, msgTy);
    }
    ++a5_weanetr->receivedData;
    switch (msgTy) {
        case 1:
        case 2:
        case 3:
        case 0xA:
        case 0xC: {
            auto f78_pSystemCallback = a5_weanetr->pSystemCallback;
            if (f78_pSystemCallback) {
                patch::protocol_dump::onRecv(playersSlot, a5_weanetr->playersSlot, msg, msgSz, "sys");
                f78_pSystemCallback(playersSlot, msg, msgSz, msgTy, a5_weanetr->f7c_pSystemCallback_owner);
            }
        }
            break;
        case 4: {  // packetTy == 3: DK2Data
            auto f68_pDataCallback = a5_weanetr->pDataCallback;
            if (f68_pDataCallback) {
                patch::protocol_dump::onRecv(playersSlot, a5_weanetr->playersSlot, msg, msgSz, NULL);
                f68_pDataCallback(msg, msgSz, playersSlot, a5_weanetr->f6c_pDataCallback_owner);
            }
        }
            break;
        case 5: {
            auto f68_pDataCallback = a5_weanetr->pGuaranteedDataCallback;
            if (f68_pDataCallback) {
                patch::protocol_dump::onRecvGuaranteed(playersSlot, a5_weanetr->playersSlot, msg, msgSz);
                f68_pDataCallback(msg, msgSz, playersSlot, a5_weanetr->pGuaranteedDataCallback_owner);
            }
        }
            break;
        case 6: {
            auto f60_pChatCallback = a5_weanetr->pChatCallback;
            if (f60_pChatCallback) {
                patch::protocol_dump::onRecv(playersSlot, a5_weanetr->playersSlot, msg, msgSz, "chat");
                f60_pChatCallback(playersSlot, msg, a5_weanetr->pChatCallback_owner);  // at least 262 bytes
            }
        }
            break;
        default:
            return;
    }
}

int dk2::WeaNetR::init() {
    this->networkService_count = 0;
    this->descArr_count = 0;
    this->selectedServiceIdx = -1;
    memset(this->services, 0, sizeof(this->services));
    this->descArr = NULL;
    this->descArr_maxCount = 0;
    net::MLDPlay *v2_MLDPlay_handle = dk2::call_new<net::MLDPlay>();
    this->mldplay = v2_MLDPlay_handle;
    if ( !v2_MLDPlay_handle ) return 0;
    if (!v2_MLDPlay_handle->StartupNetwork(dk2_MLDPlay_HandleMessage_callback)) {
        dk2::operator_delete(this->mldplay);
        this->mldplay = NULL;
        return FALSE;
    }
    net::MLDPlay *handle = this->mldplay;
    this->dword_4 = 1;
    this->networkService_count = 0;
    this->selectedServiceIdx = -1;
    handle->EnumerateServices(dk2_MLDPlay_EnumerateServices_callbaack, this);
    this->pChatCallback = NULL;
    this->pChatCallback_owner = NULL;
    this->pDataCallback = NULL;
    this->f6c_pDataCallback_owner = NULL;
    this->pGuaranteedDataCallback = NULL;
    this->pGuaranteedDataCallback_owner = NULL;
    this->pSystemCallback = NULL;
    this->f7c_pSystemCallback_owner = NULL;
    this->playersSlot = 0;
    return TRUE;
}

void dk2::WeaNetR::destroy() {
    if ( this->descArr ) {
        dk2::operator_delete(this->descArr);
        this->descArr_maxCount = 0;
    }
    if ( this->mldplay ) {
        this->mldplay->ShutdownNetwork();
        dk2::operator_delete(this->mldplay);
        this->mldplay = NULL;
    }
    this->dword_4 = 0;
}

int dk2::WeaNetR::reinitializeNetworkSystem() {
    net::MLDPlay *handle = this->mldplay;
    if ( !handle ) return this->init();
    handle->ShutdownNetwork();
    if (!this->mldplay->StartupNetwork(dk2_MLDPlay_HandleMessage_callback)) {
        dk2::operator_delete(this->mldplay);
        this->mldplay = NULL;
        return 0;
    }
    this->networkService_count = 0;
    this->selectedServiceIdx = -1;
    this->mldplay->EnumerateServices(dk2_MLDPlay_EnumerateServices_callbaack, this);
    return 1;
}

int dk2::WeaNetR::sendDataMessage(void *a2_data, unsigned int a3_size, unsigned int a4_playerListIdx_m1_m2) {
    patch::log::data("send ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2);
    patch::protocol_dump::onSend(this->playersSlot, a4_playerListIdx_m1_m2, a2_data, a3_size, false);

    unsigned int v7;
    unsigned int status = this->mldplay->SendData(a4_playerListIdx_m1_m2, a2_data, a3_size, 0, &v7);
    if (status != 2 && status != 0x40) {
        char *error = WeaNetR_error_to_string(status);
        char Buffer[128];
        sprintf(Buffer, "Unable to send DATA message - Error: %s\n", error);
        // logs printing intentionally deleted by Bullfrog devs
        patch::log::err(Buffer);
        patch::log::data("failed to send gdata ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2);
        return FALSE;
    }
    return TRUE;
}

int dk2::WeaNetR::sendGuaranteedData(void *a2_data, unsigned int a3_size, unsigned int a4_playerListIdx_m1_m2) {
    patch::log::gdata("send ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2);
    patch::protocol_dump::onSend(this->playersSlot, a4_playerListIdx_m1_m2, a2_data, a3_size, true);

    unsigned int v7;
    unsigned int v4_status = this->mldplay->SendData(a4_playerListIdx_m1_m2, a2_data, a3_size, 2u, &v7);
    if (v4_status != 2 && v4_status != 0x40) {
        char *error = WeaNetR_error_to_string(v4_status);
        char Buffer[128];
        sprintf(Buffer, "Unable to send GUARANTEED DATA message - %s\n", error);
        // logs printing intentionally deleted by Bullfrog devs
        patch::log::err(Buffer);
        patch::log::err(fname("failed to send data ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2));
        return FALSE;
    }
    return TRUE;
}


int dk2::WeaNetR::SetupConnection(void *a2_service_) {
    net::MyLocalService *a2_service = (net::MyLocalService *) a2_service_;
    MyAddr v21_addr;
    BfModemAddr v22_modemAddr;
    ComPortAddr v23_comPortAddr;
    DPCOMPOUNDADDRESSELEMENT elements[32];

    unsigned int elementsCount = 1;
    memset(elements, 0, sizeof(elements));
    elements[0].guidDataType = DPAID_ServiceProvider;
    elements[0].dwDataSize = 16;
    elements[0].lpData = a2_service;
    this->isDpModem = a2_service->f0_guid == DPSPGUID_MODEM;
    DPCOMPOUNDADDRESSELEMENT *pos = &elements[1];
    for (int i = 0; i < a2_service->f10_count; ++i) {
        GUID &guid = a2_service->f24_pGuid[i];
        if (guid == ::DPAID_Phone || guid == ::DPAID_PhoneW) {
            pos->guidDataType = ::DPAID_Phone;
            pos->dwDataSize = 2 * wcslen(MyResources_instance.networkCfg.modemAddr) + 2;
            pos->lpData = MyResources_instance.networkCfg.modemAddr;
            ++elementsCount;
            pos++;
            continue;
        }
        if (guid == ::DPAID_Modem || guid == ::DPAID_ModemW) {
            pos->guidDataType = DPAID_Modem;
            pos->dwDataSize = 2 * wcslen(MyResources_instance.networkCfg.modemAddr2);
            pos->lpData = MyResources_instance.networkCfg.modemAddr2;
            ++elementsCount;
            pos++;
            continue;
        }
        if (guid == ::DPAID_INet || guid == ::DPAID_INetW) {
            pos->guidDataType = ::DPAID_INet;
            DWORD v12_dataSize = 2 * wcslen(MyResources_instance.networkCfg.addrStr) + 2;
            pos->dwDataSize = v12_dataSize;
            pos->lpData = MyResources_instance.networkCfg.addrStr;
            ++elementsCount;
            pos++;
            continue;
        }
        if (guid == ::DPAID_ComPort) {
            v23_comPortAddr = MyResources_instance.networkCfg.comPortAddr;
            pos->guidDataType = ::DPAID_ComPort;
            pos->guidDataType.Data1 = sizeof(ComPortAddr);
            pos->lpData = &v23_comPortAddr;
            ++elementsCount;
            pos++;
            continue;
        }
        if (guid == net::BFAID_INet) {
            v21_addr.pAddr = MyResources_instance.networkCfg.addrStr;
            v21_addr.size = wcslen(MyResources_instance.networkCfg.addrStr);
            v21_addr.port = MyResources_instance.networkCfg.addrPort;
            pos->guidDataType = net::BFAID_INet;
            pos->dwDataSize = sizeof(MyAddr);
            pos->lpData = &v21_addr;
            ++elementsCount;
            pos++;
            continue;
        }
        if (guid == net::BFAID_MODEM) {
            pos->guidDataType = net::BFAID_MODEM;
            v22_modemAddr.addr1 = MyResources_instance.networkCfg.modemAddr2;
            pos->dwDataSize = sizeof(BfModemAddr);
            pos->lpData = &v22_modemAddr;
            v22_modemAddr.addr1_size = 2 * wcslen(MyResources_instance.networkCfg.modemAddr2) + 2;
            v22_modemAddr.addr2 = MyResources_instance.networkCfg.modemAddr;
            v22_modemAddr.addr2_size = 2 * wcslen(MyResources_instance.networkCfg.modemAddr) + 2;
            ++elementsCount;
            pos++;
            continue;
        }
    }
    size_t dplayAddrSize = 0;
    if (this->mldplay->CreateNetworkAddress(elements, elementsCount, NULL, &dplayAddrSize) != 0x10)
        return FALSE;
    auto *v14_dplayAddress = (net::MyDPlayCompoundAddress *) dk2::operator_new(dplayAddrSize);
    if (v14_dplayAddress == NULL) return FALSE;
    if (this->mldplay->CreateNetworkAddress(elements, elementsCount, v14_dplayAddress, &dplayAddrSize) != 2) {
        dk2::operator_delete(v14_dplayAddress);
        return FALSE;
    }
    if (this->mldplay->SetupConnection(v14_dplayAddress, &g_DK2_guidApplication, this) == 0) {
        dk2::operator_delete(v14_dplayAddress);
        return FALSE;
    }
    dk2::operator_delete(v14_dplayAddress);
    return TRUE;
}

int dk2::NetworkCfg::appendIpWithHostname() {
    struct WSAData WSAData;
    int result = ::WSAStartup(0x101u, &WSAData);
    if ( result )
        return result;
    char name[256];
    if ( ::gethostname(name, 256) )
        return ij_WSACleanup();
    struct hostent *v3_hostent = ::gethostbyname(name);
    const char **p_h_name = (const char **)&v3_hostent->h_name;  // Bullfrog devs mistake
    if ( !v3_hostent )
        return ::WSACleanup();
    in_addr ipv4 = *(struct in_addr *) v3_hostent->h_addr_list[0];
    patch::multi_interface_fix::replaceLocalIp(v3_hostent, ipv4.S_un.S_addr);

    char *v5_ipAddr = ::inet_ntoa(ipv4);
    strcpy(this->ipAddr, "IP: ");
    strcat(this->ipAddr, v5_ipAddr);
    strcpy(this->localMachineName, *p_h_name);
    return ::WSACleanup();
}

int dk2::WeaNetR::getCurrentPlayersCount(uint32_t *a2_pPlayersCount) {
    net::MLDPLAY_SESSIONDESC desc;
    DWORD size = sizeof(net::MLDPLAY_SESSIONDESC);
    if (this->mldplay->GetSessionDesc(&desc, &size) != 2) return 0;
    *a2_pPlayersCount = desc.currentPlayers;
    return 1;
}

int dk2::WeaNetR::collectPlayerInfo(WeanetrPlayerInfo *a2_playerInfoArr, uint32_t *a3_outCount) {
    net::MLDPLAY_PLAYERINFO v12_playerInfoArr[8];
    memset(v12_playerInfoArr, 0, sizeof(v12_playerInfoArr));
    if (this->mldplay->GetPlayerInfo(v12_playerInfoArr)) {
        int v4_count = 0;
        net::MLDPLAY_PLAYERINFO *v5_plinfPos = v12_playerInfoArr;
        int v6_left = 8;
        do {
            if ((v5_plinfPos->f0_flags & 0xF) != 0)
                ++v4_count;
            ++v5_plinfPos;
            --v6_left;
        } while (v6_left);
        this->joinedPlayersCount = v4_count;
        memcpy(this->playerInfo, v12_playerInfoArr, sizeof(this->playerInfo));
    }
    net::MLDPLAY_PLAYERINFO *p_f5_slotNo = (net::MLDPLAY_PLAYERINFO *) &this->playerInfo[0];
    int v8_count = 0;
    int v11_left = 8;
    WeanetrPlayerInfo *p_f48_slotNo = a2_playerInfoArr;
    do {
        if ((p_f5_slotNo->f0_flags & 0xF) != 0) {
            p_f48_slotNo->playerId = p_f5_slotNo->f26_playerId_slot.value;
            p_f48_slotNo->slotNo = p_f5_slotNo->f5_slotNo;
            p_f48_slotNo->playersCount = (unsigned __int8) p_f5_slotNo->f0_flags >> 4;
            wcsncpy(p_f48_slotNo->shortName, p_f5_slotNo->f6_shortName, 31u);
            p_f48_slotNo->val0 = 0;
            p_f48_slotNo->val1 = 1;
            ++v8_count;
            ++p_f48_slotNo;
        }
        ++p_f5_slotNo;
        --v11_left;
    } while (v11_left);
    int result = 1;
    *a3_outCount = v8_count;
    return result;
}

int dk2::WeaNetR::getPlayerInfo() {
    net::MLDPLAY_PLAYERINFO playerInfoArr[8];
    memset(playerInfoArr, 0, sizeof(playerInfoArr));
    if (this->mldplay->GetPlayerInfo(playerInfoArr)) {
        int playersCount = 0;
        for (int i = 0; i < 8; ++i) {
            net::MLDPLAY_PLAYERINFO *plinf = &playerInfoArr[i];
            if ((plinf->f0_flags & 0xF) == 0) continue;
            ++playersCount;
        }
        this->joinedPlayersCount = playersCount;
        memcpy(this->playerInfo, playerInfoArr, sizeof(this->playerInfo));
        return 1;
    }
    return 0;
}

int dk2::WeaNetR::updatePlayers_isHost() {
    net::MLDPLAY_PLAYERINFO playerInfoArr[8];
    memset(playerInfoArr, 0, sizeof(playerInfoArr));
    if (this->mldplay->GetPlayerInfo(playerInfoArr)) {
        int joinedCount = 0;
        for (int i = 0; i < 8; ++i) {
            net::MLDPLAY_PLAYERINFO *plinf = &playerInfoArr[i];
            if ((plinf->f0_flags & 0xF) == 0) continue;
            ++joinedCount;
        }
        this->joinedPlayersCount = joinedCount;
        memcpy(this->playerInfo, playerInfoArr, sizeof(this->playerInfo));
    }

    auto *playerinfo = (net::MLDPLAY_PLAYERINFO *) &this->playerInfo[this->playersSlot];
    return (uint8_t) playerinfo->f0_flags >> 4;
}

int dk2::WeaNetR::getCurrentPlayerIdx() {
    net::MLDPLAY_PLAYERINFO playerInfoArr[8];
    memset(playerInfoArr, 0, sizeof(playerInfoArr));
    if (this->mldplay->GetPlayerInfo(playerInfoArr)) {
        int playerCount = 0;
        for (int i = 0; i < 8; ++i) {
            net::MLDPLAY_PLAYERINFO *plinf = &playerInfoArr[i];
            if ((plinf->f0_flags & 0xF) == 0) continue;
            ++playerCount;
        }
        this->joinedPlayersCount = playerCount;
        memcpy(this->playerInfo, playerInfoArr, sizeof(this->playerInfo));
    }

    int v5_k = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        net::MLDPLAY_PLAYERINFO *plInf = (net::MLDPLAY_PLAYERINFO *) &this->playerInfo[i];
        if ((plInf->f0_flags & 0xF) == 0) continue;
        if ((uint8_t) plInf->f5_slotNo == this->playersSlot) return v5_k;
        ++v5_k;
    }
    return 0;
}

int dk2::WeaNetR::createSession(
        wchar_t *a2_gameName,
        wchar_t *a3_playerName,
        uint32_t *a4_pPlayers,
        int a5_maxPlayers) {
    net::MySessionCredentials v8_cred;
    memset(&v8_cred, 0, sizeof(v8_cred));
    v8_cred.f0_credentialParameterSize = sizeof(MySessionCredentials);
    v8_cred.field_18 = 0;
    v8_cred.f4_dk2Version = g_minorVersion | (g_majorVersion << 16);
    v8_cred.f10_totalMaxPlayers = a5_maxPlayers;
    v8_cred.f14__totalMaxPlayers2 = a5_maxPlayers;
    while(true) {
        int v6 = this->mldplay->CreateSession((DWORD *) a4_pPlayers, a2_gameName, a3_playerName, &v8_cred, 4u);
        if (v6 == 1) continue;
        if (v6 != 2) return 0;
        break;
    }
    this->playersSlot = *a4_pPlayers;
    return 1;
}


BOOL dk2::WeaNetR::isPlayerJoined(unsigned int a2_slot) {
    net::MLDPLAY_PLAYERINFO playerinfo;
    return this->mldplay->GetPlayerDesc(&playerinfo, a2_slot) == 2;
}

namespace dk2 {
    void __stdcall EnumerateSessions_callback(net::MLDPLAY_SESSIONDESC *a1_sessionDesc, void *arg) {
        WeaNetR *self = (WeaNetR *) arg;
        unsigned int f5C_descArr_maxCount = self->descArr_maxCount;
        if (!f5C_descArr_maxCount || self->descArr_count >= f5C_descArr_maxCount) {
            int v4_maxCount = 64;
            if (f5C_descArr_maxCount)
                v4_maxCount = f5C_descArr_maxCount + 64;
            MLDPLAY_SESSIONDESC *v5_descBuf = (MLDPLAY_SESSIONDESC *) dk2::operator_new(sizeof(MLDPLAY_SESSIONDESC) * v4_maxCount);
            if (v5_descBuf) {
                memcpy(v5_descBuf, self->descArr, 0xA4 * self->descArr_maxCount);
                dk2::operator_delete(self->descArr);
                self->descArr = v5_descBuf;
                self->descArr_maxCount = v4_maxCount;
            }
        }
        DWORD f54_descArr_count = self->descArr_count;
        if (f54_descArr_count < self->descArr_maxCount) {
            memcpy(
                    &self->descArr[f54_descArr_count],
                    a1_sessionDesc,
                    sizeof(self->descArr[f54_descArr_count]));
            ++self->descArr_count;
        }
    }
}

BOOL dk2::WeaNetR::collectNetworkSessions() {
    net::MLDPlay *fc_MLDPlay_handle = this->mldplay;
    this->descArr_count = 0;
    int v3_status = fc_MLDPlay_handle->EnumerateSessions(0, EnumerateSessions_callback, 0, this);
    if (v3_status == 1) return 0;
    if (v3_status != 2) return 0;
    if (!this->isDpModem) return 1;
    if (this->descArr_count) return 1;
    DWORD TimeMs = getTimeMs();
    process_win_inputs();
    if (this->descArr_count) return 1;
    while (this->mldplay->EnumerateSessions(0, EnumerateSessions_callback, 0, this) == 2) {
        if (getTimeMs() - TimeMs >= 10000)
            return this->descArr_count != 0;
        process_win_inputs();
        if (!this->descArr_count)
            continue;
        return this->descArr_count != 0;
    }
    return 0;
}

int dk2::WeaNetR::enumerateSessions(int a2) {
    this->descArr_count = 0;
    unsigned int flags = a2 ? 2 : 4;
    int status = this->mldplay->EnumerateSessions(0, EnumerateSessions_callback, flags, this);
    process_win_inputs();
    return status;
}

int dk2::WeaNetR::joinNetworkSession(
        FoundSessionDesc *a2_foundDesc,
        wchar_t *a3_playerName,
        unsigned int *a4_pPlayersCount) {
    if (!a3_playerName)
        return 0;
    net::MySessionCredentials v7_cred;
    memset(&v7_cred, 0, sizeof(v7_cred));
    v7_cred.f0_credentialParameterSize = sizeof(net::MySessionCredentials);
    v7_cred.f4_dk2Version = g_minorVersion | (g_majorVersion << 16);
    int v6_status;
    do {
        v6_status = this->mldplay->JoinSession(
                (net::MLDPLAY_SESSIONDESC *) a2_foundDesc->desc,
                (DWORD *) a4_pPlayersCount,
                a3_playerName,
                &v7_cred
        );
    } while (v6_status == 1);
    if (v6_status != 2)
        return 0;
    this->playersSlot = *a4_pPlayersCount;
    return 1;
}

int dk2::WeaNetR::sendChatMessage(uint16_t *a2_chatMessage, unsigned int playerListIdx_m1_m2) {
    unsigned int ignored;
    unsigned int status = this->mldplay->SendChat(playerListIdx_m1_m2, (wchar_t *) a2_chatMessage, 0, &ignored);
    if (status == 2 || status == 0x40)
        return 1;
    char *errorStr = WeaNetR_error_to_string(status);
    char Buffer[128];
    sprintf(Buffer, "Unable to send CHAT message - Error:%s\n", errorStr);
    // logs printing intentionally deleted by Bullfrog devs
    patch::log::err(Buffer);
    return 0;
}

