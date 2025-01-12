//
// Created by DiaLight on 17.12.2024.
//

#ifndef FLAME_NETWORKSERVICEPROVIDER_H
#define FLAME_NETWORKSERVICEPROVIDER_H

#include <Windows.h>
#include <thread>
#include "protocol.h"
#include "structs.h"
#include "dplobby.h"

namespace net {

class MyPlayerDesc;
class MyDPlayCompoundAddress;
class ScheduledPacket;

#undef SendMessage

#pragma pack(push, 1)
class NetworkServiceProvider {
public:

    void *f4_arg = NULL;
    CRITICAL_SECTION dataLock;
    int f20_isServiceProviderInitialized = FALSE;
    MyPlayerDesc *f24_playerList = NULL;
    PlayerId f28_host_playerId;

    // 00559ED0 MLDPlay_HandleMessage_callback

    // weanetr->f70_pGuaranteedDataCallback
    // 00542F40 CFrontEndComponent_guaranteedDataCallback
    // 00528120 CNetworkComponent_guaranteedDataCallback

    // playersSlot, msg, msgSz, msgTy, weanetr
    // 1: weanetr->f78_pSystemCallback
    //   [nsp=1000C341,dplay=10007D9C,bfnet=1000439E]
    // 2: weanetr->f78_pSystemCallback
    //   [nsp=1000C428,dplay=10007C3D,
    //     bfnet=10004665,bfnet2=100044DC,bfnet3=10003C45]
    // 3: weanetr->f78_pSystemCallback
    // 4: weanetr->f68_pDataCallback
    //   [nsp=1000C521,nsp2=1000C9AD]
    // 5: weanetr->f70_pGuaranteedDataCallback  net=00528120  front=00542F40
    //   [nsp=1000D49B,nsp2=1000DA1D,nsp3=1000DDC6]
    // 6: weanetr->f60_pChatCallback
    //   [nsp=1000C50F,nsp2=1000CB5E]
    // A: weanetr->f78_pSystemCallback
    //   [dplay=10007F3B,bfnet=10003CD0]
    // C: weanetr->f78_pSystemCallback
    MessageHandlerType messageHandler;

    MyDPlayCompoundAddress *f30_dPlayAddr = NULL;
    GUID f34_guidPlayer;
    GUID f44_guidApplication;
    int f54_host_ipv4;
    __int16 f58_host_portBe;
    int f5A_ackPacketCount_perPlayerSlot[32];
    int fDA_unused1_perPlayerSlot[32];
    int f15A_ignored_inNewSession;
    int f15E_nextAckIdx;
    HANDLE f162_DestroySPSession_hEvent = NULL;
    HANDLE h166_OnStopDeliverThread_hEvent = NULL;
    HANDLE f16A_playerCountChange_hEvent = NULL;
    HANDLE f16E_OnUnused_hEvent = NULL;
    HANDLE f172_OnPlayerJoined_hEvent = NULL;
    HANDLE f176_OnTerminateNspThread_hEvent = NULL;
    HANDLE f17a_OnPacket_D_Guaranteed_added_hEvent = NULL;
    HANDLE f17e_NetworkServiceProvider_hThread = INVALID_HANDLE_VALUE;
    int f182_unused2;
    MLDPLAY_SESSIONDESC f186_sessionDesc;
    MyCurPlayerInfo f226_curPlayer;
    MLDPLAY_SYSTEMQUEUE f257_toHandleList;
    MLDPLAY_SYSTEMQUEUE f25F_deliverHeadersQueue;
    MLDPLAY_SYSTEMQUEUE f267_receivedDeliverQueue;
    ScheduledPacket *f26F_packetSendToAllArr[50];
    ScheduledPacket *f337_packetSendQueue = NULL;
    MyPacket_C_HandledPackets f33B_packet;
    int f413_AckPacketsCountArr_idx;
    int f417_unused3 = 0;
    HANDLE f41B_SendDeliverThread_hThread = INVALID_HANDLE_VALUE;
    wchar_t f41F_password[32];
    int f45F_getHostByName_isPresent = FALSE;
    char f463_getHostByName_host[256] = {0};
    uint16_t f563_getHostByName_port = 7575;

    virtual int Startup(MessageHandlerType handler);
    virtual int ShutDown();

    virtual int SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) = 0;

    typedef void (__stdcall *ServiceEnumCallback)(
            MyLocalService *a1_service, wchar_t *name,
            GUID *a3_guid, DWORD a4_idx, void *arg);
    virtual int EnumerateLocalServices(ServiceEnumCallback a2_fun, void *a3_arg) = 0;

    virtual int BuildSession(
            MessageHandlerType handler, GUID *guid, char *a4_outNGLD, DWORD *a5_outPlayers,
            wchar_t *a6_outGameName, wchar_t *a7_outPlayerName,
            int a8_totalMaxPlayers, int a9_ignore) = 0;
    virtual int enumLocalApplications(int a2, int a3) = 0;
    virtual int connectLobby(
            int a2_flags, WCHAR *a3_sessionName, WCHAR *a4_playerName,
            GUID *a5_guidApplication, wchar_t *a6_address,
            int a7, int a8_maxPlayers) = 0;

    virtual int CreateSPSession(
            DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
            MySessionCredentials *a5_cred, int a6_flags) = 0;

    virtual int JoinSPSession(
            MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount,
            wchar_t *a4_playerName, MySessionCredentials *a5_cred) = 0;
    virtual int DestroySPSession() = 0;

    virtual int EnumerateSessions(
            DWORD a2_timeout, EnumerateSessionsCallback a3_callback,
            int a4_flags, void *a5_arg) = 0;
    virtual int getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) = 0;
    virtual int setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) = 0;
    virtual int DestroySession(unsigned int a2_slot) = 0;

    virtual void EnableNewPlayers(int a2_enabled) = 0;

    virtual int EnumPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg) = 0;  // bfnet=10003330 dplay=100074D0
    virtual BOOL SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) = 0;  // bfnet=10003510 dplay=10007680
    BOOL SendMessage(PlayerId a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) {
        return SendMessage(a2_playerId_slot.value, a3_buf, a4_size, a5_ignored);
    }
    virtual int SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) = 0;  // bfnet=10003650 dplay=10007750
    virtual PacketHeader *ReadSPMessage() = 0;
    virtual void setNewHost(MyPacket_E_NewHost *a2_packet) = 0;
    virtual int SendMSResults(const char *a2_message) = 0;


    typedef void (__stdcall *EnumerateNetworkMediumsCallback)(unsigned __int16 *, void *);
    virtual unsigned int EnumerateNetworkMediums(EnumerateNetworkMediumsCallback a2, void *a3) = 0;
    virtual int EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) = 0;
    virtual int CreateCompoundAddress(
            DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
            MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) = 0;  // bfnet=10003DE0 dplay=10008180
    virtual unsigned int __getHiWord(PlayerId playerId) = 0;
    virtual PacketHeader *_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) = 0;

    int destroySystemThread();
    int destroyMainThread();
    int Destroy();

    void processSPMessages();

    int CreateServiceProvider();

    void SendDeliverThread();

    int startSendDeliverThread();

    int CreateSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName, MySessionCredentials *a5_cred, int a6_flags);

    int GetAllPlayersInfo(DWORD *a2_outCurPlayerSlot);

    int JoinSession(MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName, MySessionCredentials *a5_cred);

    void initGetHostByName(const char *a2_host, uint16_t a3_port) {
        if (!this->f20_isServiceProviderInitialized) return;
        ::strcpy(this->f463_getHostByName_host, a2_host);
        this->f563_getHostByName_port = a3_port;
        this->f45F_getHostByName_isPresent = 1;
    }

    void schedulePlayersChangePacket(
            int a2_type, PlayerId a3_playerId_slot, int a4_playerSlot,
            wchar_t *a5_playerName, int a6_flags);

    void queuePacketToSend(ScheduledPacket *toAdd);
    void send_B_PlayerList(int a2_slot);
    void releasePacketSendArr();
    void releasePacketSendArr_forPlayer(char a2_slotId);
    void handlePacket_C(MyPacket_C_HandledPackets *a2_packet);

    void releaseToHandleList();
    int handlePacket_1_2_9_B_E(PacketHeader *packet, unsigned int a3_size, MySocket *a4_sock);


    void handlePacket_D_locked(MyPacket_D_Guaranteed *a2_packet);
    void handlePacket_D(MyPacket_D_Guaranteed *a2_packet);

    void handlePacket_10_handleData();
    void handlePacket_10(MyPacket_10_GuaranteedProgress *packet);
    void sendScheduledPacketToAllPlayers(ScheduledPacket *a2_scheduledPacket);

    int hasJoinedPlayer(PlayerId a2_playerId_slot);

    ///
    /// add items 1000CBD0
    /// release 1000D020
    /// handle packet_10 1000DAD0  send=1000D901
    ///
    int processDeliverHeaders(MLDPLAY_SYSTEMQUEUE *a2_deliverHeadersQueue, DWORD a3_sysTime_ms, DWORD *a4_pSizeLeft);

    void releasePacketSendQueue();

    void releaseDeliverQueues();

    int AreWeLobbied( MessageHandlerType a2_messageHandler, GUID *a3_guid, char *a4_outNGLD, DWORD *a5_outPlayers,
                      wchar_t *a6_gameName, wchar_t *a7_playerName, int a8_totalMaxPlayers, int a9_ignore);

    int popReceivedPacketToHandle(PacketHeader *packet);


    int enumAllPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg);

    int SendData(unsigned int a2_playerListIdx_m1_m2, const void *a3_data, size_t Size, int a5_flags, unsigned int *a6_outGuaranteedCount);

    int SendDataGuaranteed(unsigned int a2_playerListIdx_m1_m2, const void *a3_data, size_t Size, int a5_flags, unsigned int *a6_outGuaranteedCount);

    int SendDataDatagram(int a2_playerListIdx_m1_m2, const void *a3_data, size_t a4_size, int a5_flags, unsigned int *a6_outGuaranteedCount);

    int SendChat(unsigned int a2_FFFF, wchar_t *chatMesage, int a4_ignored1, unsigned int *a5_ignored2);

    int AddGuaranteedPacketToMessageQueue(unsigned int a2_playerListIdx_m1_m2, const void *a3_data, size_t a4_dataSize, unsigned int *a5_outGuaranteedIdx);

};
#pragma pack(pop)
static_assert(sizeof(NetworkServiceProvider) == 0x565);

}  // namespace net

#endif //FLAME_NETWORKSERVICEPROVIDER_H
