//
// Created by DiaLight on 09.01.2025.
//

#ifndef FLAME_DPLAY_H
#define FLAME_DPLAY_H


#include "NetworkServiceProvider.h"

namespace net {

#pragma pack(push, 1)
class DPlay : public NetworkServiceProvider {
public:
    HANDLE f565_hEvent = NULL;
    IDirectPlay4 *f569_pIDirectPlay4 = NULL;
    IDirectPlayLobby3 *f56d_pIDirectPlayLobby3 = NULL;
    DPSESSIONDESC2 f571_desc;
    void *f5C1_ptr_eos = NULL;

    int Startup(MessageHandlerType handler) override;

    int ShutDown() override;

    int SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) override;

    int EnumerateLocalServices(ServiceEnumCallback a2_fun, void *a3_arg) override;

    int BuildSession(MessageHandlerType handler, GUID *guid, char *a4_outNGLD, DWORD *a5_outPlayers,
                     wchar_t *a6_outGameName, wchar_t *a7_outPlayerName, int a8_totalMaxPlayers,
                     int a9_ignore) override;

    int enumLocalApplications(int a2, int a3) override;

    int connectLobby(int a2_flags, WCHAR *a3_sessionName, WCHAR *a4_playerName, GUID *a5_guidApplication,
                     wchar_t *a6_address, int a7, int a8_maxPlayers) override;

    int
    CreateSPSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName, MySessionCredentials *a5_cred,
                    int a6_flags) override;

    int JoinSPSession(MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName,
                      MySessionCredentials *a5_cred) override;

    int DestroySPSession() override;

    int EnumerateSessions(DWORD a2_timeout, EnumerateSessionsCallback a3_callback, int a4_flags, void *a5_arg) override;

    int getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) override;

    int setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) override;

    int DestroySession(unsigned int a2_slot) override;

    void EnableNewPlayers(int a2_enabled) override;

    int EnumPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg) override;

    BOOL SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) override;

    int SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) override;

    PacketHeader *ReadSPMessage() override;

    void setNewHost(MyPacket_E_NewHost *a2_packet) override;

    int SendMSResults(const char *a2_message) override;

    unsigned int EnumerateNetworkMediums(EnumerateNetworkMediumsCallback a2, void *a3) override;

    int EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) override;

    int CreateCompoundAddress(DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
                              MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) override;

    unsigned int __getHiWord(PlayerId playerId) override;

    PacketHeader *_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) override;

};
#pragma pack(pop)
static_assert(sizeof(DPlay) == 0x5C5);

}  // namespace net

#endif //FLAME_DPLAY_H
