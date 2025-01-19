//
// Created by DiaLight on 09.01.2025.
//

#include "dk2/network/WeaNetR.h"
#include "dk2/network/MyAddr.h"
#include "dk2/network/BfModemAddr.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/weanetr_dll/MLDPlay.h"
#include "patches/weanetr_dll/globals.h"
#include "dk2_memory.h"
#include "tools/hexdump.hpp"
#include "dplobby.h"
#include "dplay.h"
#include "patches/logging.h"


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
//    patch::log::dbg("* data recv ty=%X sz=%X pl=%X  hty=%X", (int) (*(uint8_t *) a2_messsage), a3_messageSize, a1_playersSlot, a4_messageType);
    ++a5_weanetr->receivedData;
    switch (msgTy) {
        case 1:
        case 2:
        case 3:
        case 0xA:
        case 0xC: {
            auto f78_pSystemCallback = a5_weanetr->pSystemCallback;
            if (f78_pSystemCallback)
                f78_pSystemCallback(playersSlot, msg, msgSz, msgTy, a5_weanetr->f7c_pSystemCallback_owner);
        }
            break;
        case 4: {  // packetTy == 3: DK2Data
            auto f68_pDataCallback = a5_weanetr->pDataCallback;
            if (f68_pDataCallback) {
                f68_pDataCallback(msg, msgSz, playersSlot, a5_weanetr->f6c_pDataCallback_owner);
            }
        }
            break;
        case 5: {
            auto f68_pDataCallback = a5_weanetr->pGuaranteedDataCallback;
            if (f68_pDataCallback) {
                f68_pDataCallback(msg, msgSz, playersSlot, a5_weanetr->pGuaranteedDataCallback_owner);
            }
        }
            break;
        case 6: {
            auto f60_pChatCallback = a5_weanetr->pChatCallback;
            if (f60_pChatCallback)
                f60_pChatCallback(playersSlot, msg, a5_weanetr->pChatCallback_owner);  // at least 262 bytes
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
        operator delete(this->mldplay);
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
        operator delete(this->mldplay);
        this->mldplay = NULL;
        return 0;
    }
    this->networkService_count = 0;
    this->selectedServiceIdx = -1;
    this->mldplay->EnumerateServices(dk2_MLDPlay_EnumerateServices_callbaack, this);
    return 1;
}

int dk2::WeaNetR::sendDataMessage(void *a2_data, unsigned int a3_size, unsigned int a4_playerListIdx_m1_m2) {
//    patch::log::dbg("* data send ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2);

    unsigned int v7;
    unsigned int status = this->mldplay->SendData(a4_playerListIdx_m1_m2, a2_data, a3_size, 0, &v7);
    if (status == 2 || status == 0x40)
        return 1;
    char *error = WeaNetR_error_to_string(status);
    char Buffer[128];
    sprintf(Buffer, "Unable to send DATA message - Error: %s\n", error);
    // logs printing intentionally deleted by Bullfrog devs
    patch::log::err(Buffer);
    return 0;
}

int dk2::WeaNetR::sendGuaranteedData(void *a2_data, unsigned int a3_size, unsigned int a4_playerListIdx_m1_m2) {
//    patch::log::dbg("* guar send ty=%X sz=%X pl=%X", (int) (*(uint8_t *) a2_data), a3_size, a4_playerListIdx_m1_m2);

    unsigned int v7;
    unsigned int v4_status = this->mldplay->SendData(a4_playerListIdx_m1_m2, a2_data, a3_size, 2u, &v7);
    if (v4_status == 2 || v4_status == 0x40)
        return 1;
    char *error = WeaNetR_error_to_string(v4_status);
    char Buffer[128];
    sprintf(Buffer, "Unable to send GUARANTEED DATA message - %s\n", error);
    // logs printing intentionally deleted by Bullfrog devs
    patch::log::err(Buffer);
    return 0;
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
    int result = WSAStartup(0x101u, &WSAData);
    if ( result )
        return result;
    char name[256];
    if ( ::gethostname(name, 256) )
        return ij_WSACleanup();
    struct hostent *v3_hostent = ::gethostbyname(name);
    const char **p_h_name = (const char **)&v3_hostent->h_name;  // Bullfrog devs mistake
    if ( !v3_hostent )
        return ::WSACleanup();
    char *v5_ipAddr = ij_inet_ntoa(**(struct in_addr **)v3_hostent->h_addr_list);

//    for(int i = 0; ; ++i) {
//        in_addr *addr = (in_addr *) v3_hostent->h_addr_list[i];
//        if(addr == NULL) break;
//        v5_ipAddr = ij_inet_ntoa(*addr);
//    }
    strcpy(this->ipAddr, "IP: ");
    strcat(this->ipAddr, v5_ipAddr);
    strcpy(this->localMachineName, *p_h_name);
    return ij_WSACleanup();
}
