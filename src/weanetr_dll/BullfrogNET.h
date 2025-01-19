//
// Created by DiaLight on 08.11.2024.
//

#ifndef FLAME_BULLFROGNET_H
#define FLAME_BULLFROGNET_H

#include "NetworkServiceProvider.h"
#include "DnsResolver.h"

namespace net {

class DnsResolver;

#pragma pack(push, 1)
class BullfrogNET : public NetworkServiceProvider {
public:
    PacketHeader *f565_recvdData = NULL;
    PlayerId f569_last_playerId_slot;
    DnsResolver *f56d_pAddress = NULL;
    MySocket f571_joinSession_sock;
    MySocket f57B_enumerateSessions_sock = {0, INVALID_SOCKET, 0};
    MySocket f585_listenThread_sock;
    int f58F_flags;
    ListEntry_SessionDesc *f593_sessionList = NULL;
    HANDLE f597_listenThread_hThread = INVALID_HANDLE_VALUE;
    HANDLE f59B_joinSession_hThread = INVALID_HANDLE_VALUE;
    HANDLE f59F_enumerateSessions_hThread = INVALID_HANDLE_VALUE;
    int dword_5a3 = 0;
    char f5A7_dst_addrStr_by_getHostByName[20] = {0};
    char f5bb_lpClassName[32] = {0};
    HWND f5db_getHostByName_async_hWnd = NULL;
    HANDLE h5df_getHostByName_async_taskHandle = NULL;
    char f5E3_g_addr[64] = {0};
    char f623_l_addr[64] = {0};
    char f663_n_addr[16] = {0};
    char f673_SendMS_addr[64] = {0};
    MyAddrStruc f6B3_myaddr;
    MMTIME f6CB_sysTime;

    int Startup(MessageHandlerType handler) override;
    int ShutDown() override;

    void getHostByname_destroy();
    void clearSessionList();
    int waitResetSessions(int a2_clearSessions);

    int BuildSession(
            MessageHandlerType handler, GUID *guid, char *a4_outNGLD, DWORD *a5_outPlayers,
            wchar_t *a6_outGameName, wchar_t *a7_outPlayerName,
            int a8_totalMaxPlayers, int a9_ignore) override;

    int enumLocalApplications(int a2, int a3) override { return 0; }

    int connectLobby(
            int a2_flags, WCHAR *a3_sessionName, WCHAR *a4_playerName,
            GUID *a5_guidApplication, wchar_t *a6_address, int a7, int a8_maxPlayers
    ) override { return 0x20; }

    int SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) override;
    int EnumerateLocalServices(ServiceEnumCallback a2_fun, void *a3_arg) override;

    void genRandomGuid(GUID *guid);
    int startGetHostByNameAsync();
    int getHostByName_async(char *hostName);

    int CreateSPSession(
            DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
            MySessionCredentials *a5_cred, int a6_flags) override;

    void JoinSession_proc();

    void waitForThreadExit_JoinSession();
    int JoinSPSession(
            MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount,
            wchar_t *a4_playerName, MySessionCredentials *a5_cred) override;

    void DestroyPlayer();

    void listenThread_waitDestroy();
    int DestroySPSession() override;


    void handleSessionPacket(MyPacket_6_sessionDesc *packet, mmtime_tag &sysTime);
    void EnumerateSessions_proc();
    
    int EnumerateSessions2(
            DWORD *a2_pTimeout, MySocket *a3_lobbySock_dst, int a4_callback,
            char *hostname, __int16 a6_flags, void *a7_arg);

    BOOL getHostByName_collectResults();

    int EnumerateSessions_impl(
            DWORD a2_timeout, EnumerateSessionsCallback a3_callback,
            int a4_flags, void *a5_arg, char *f0_pAddr);
    int EnumerateSessions(
            DWORD a2_timeout, EnumerateSessionsCallback a3_callback,
            int a4_flags, void *a5_arg) override;

    int EnumPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg) override;
    void EnableNewPlayers(int a2_enabled) override;
    PacketHeader *_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) override;
    BOOL SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) override;
    BOOL SendMessage(PlayerId a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) {
        return SendMessage(a2_playerId_slot.value, a3_buf, a4_size, a5_ignored);
    }
    int SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) override;

    int isCriticalError();
    void handlePacket_5_SessionRequest(MySocket *a2_to, MyPacket_5_SessionRequest *a3_packet, unsigned int a4_packetSize);
    void handlePacket_7_JoinPlayer(MyPacket_7_Join *a2_joinPacket, MySocket *a2_to);
    void handlePacket_A_DestroyPlayer(MyPacket_A_DestroyPlayer *packet, unsigned int a3_size, MySocket *a2_to);

    PacketHeader *handleLobbyPacket(PacketHeader *packet, int size, MySocket &sockSrc);
    PacketHeader *handleNotLobbyPacket(PacketHeader *packet, int size, MySocket &sockSrc);

    void ListenThread_proc();
    void CreateListenServer();

    PacketHeader *ReadSPMessage() override;

    unsigned int EnumerateNetworkMediums(EnumerateNetworkMediumsCallback a2, void *a3) override { return 0x20; }
    int EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) override { return 0x20; }

    unsigned int __getHiWord(PlayerId playerId) override {
        return playerId.slotIdx;
    }

    void sendPacket_6_SessionDesc();

    int DestroySession(unsigned int a2_slot) override;

    int destroyPlayer(unsigned int a2_slot);

    int getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) override;

    int setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) override;

    void setNewHost(MyPacket_E_NewHost *a2_packet) override;

    int SendMSResults(const char *a2_message) override;

    int CreateCompoundAddress(DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
                              MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) override;

};
#pragma pack(pop)
static_assert(sizeof(BullfrogNET) == 0x6D7);

}  // namespace net

#endif //FLAME_BULLFROGNET_H
