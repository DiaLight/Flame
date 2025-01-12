//
// Created by DiaLight on 19.12.2024.
//

#ifndef FLAME_MLDPLAY_H
#define FLAME_MLDPLAY_H

#include <Windows.h>
#include "structs.h"
#include "dplobby.h"

namespace net {

    class MyLocalService;
    class NetworkServiceProvider;

#pragma pack(push, 1)
class MLDPlay {
public:
    MyLocalService *f0_service_first = NULL;
    NetworkServiceProvider *f4_pNetworkServiceProvider = NULL;
    MessageHandlerType f8_messageHandler;
    int fc_hasHandler = 0;
    int dword_10 = 0;
    int dword_14 = 0;
    int field_18;
    int dword_1c = -1;
    uint8_t f20_unk[0x1A6];

    MLDPlay &operator=(const MLDPlay &that) {
        memcpy(this, &that, 0x1C6u);
        return *this;
    }

    // DKII.EXE import: ordinal=44 name=?StartupNetwork@MLDPlay@@QAEHP6GXKPAXKK0@Z@Z
    int StartupNetwork(MessageHandlerType messageHandler);

    // DKII.EXE import: ordinal=43 name=?ShutdownNetwork@MLDPlay@@QAEHXZ
    int ShutdownNetwork();

    // DKII.EXE import: ordinal=42 name=?SetupConnection@MLDPlay@@QAEHPAXPAU_GUID@@0@Z
    int SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg);

    // DKII.EXE import: ordinal=21 name=?EnumerateServices@MLDPlay@@QAEHP6GXPAXPAGPAU_GUID@@K0@Z0@Z
    int EnumerateServices(EnumerateServicesCallback a2_callback, void *a3_arg);

    void serviceCallback(MyLocalService *a1_service, wchar_t *name, GUID *a3_guid, unsigned int a4_idx);

    int AreWeLobbied(MessageHandlerType messageHandler, GUID *a3_guid, char *a4_outNGLD, DWORD *a5_outPlayers, wchar_t *a6_gameName, wchar_t *a7_playerName, unsigned int a8_totalMaxPlayers, unsigned int a9_ignore);

    int EnumerateLobbyApplications(
            MessageHandlerType a2_messageHandler,
            EnumerateSessionsCallback a3_ignore,
            void *a4_ignore);

    int RunLobbyApplication(int a2_flags, wchar_t *a3_sessionName, wchar_t *a4_playerName, GUID *a5_guidApplication,
                            wchar_t *a6_address, unsigned int a7_ignore, unsigned int a8_maxPlayers);

    BOOL IsProviderInitialised();

    // DKII.EXE import: ordinal=12 name?CreateSession@MLDPlay@@QAEHPAKPAG1PAXK@Z
    int CreateSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName, MySessionCredentials *a5_cred, unsigned int a6_flags);

    // DKII.EXE import: ordinal=29 name=?JoinSession@MLDPlay@@QAEHPAUMLDPLAY_SESSIONDESC@@PAKPAGPAX@Z
    int JoinSession(struct MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName, MySessionCredentials *a5_cred);

    // DKII.EXE import: ordinal=14 name=?DestroySession@MLDPlay@@QAEHXZ
    int DestroySession();

    // DKII.EXE import: ordinal=22 name=?EnumerateSessions@MLDPlay@@QAEHKP6GXPAUMLDPLAY_SESSIONDESC@@PAX@ZK1@Z
    int EnumerateSessions(unsigned int a2_zero, EnumerateSessionsCallback a3_callback, unsigned int a4_flags, void *a5_arg);

    int EnumeratePlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, unsigned int a4_ignored, void *a5_arg);

    // DKII.EXE import: ordinal=36 name=?SendData@MLDPlay@@QAEHKPAXKKPAK@Z
    int SendData(unsigned int a2_playerListIdx_m1_m2, void *a3_data, size_t Size, unsigned int a5_flags, unsigned int *a6_outGuaranteedCount);

    // DKII.EXE import: ordinal=35 name=?SendChat@MLDPlay@@QAEHKPAGKPAK@Z
    int SendChat(unsigned int a2_FFFF, wchar_t *chatMessage, unsigned int a4_ignored1, unsigned int *a5_ignored2);

    // DKII.EXE import: ordinal=27 name=?GetSessionDesc@MLDPlay@@QAEKPAUMLDPLAY_SESSIONDESC@@PAK@Z
    int GetSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize);

    // DKII.EXE import: ordinal=41 name=?SetSessionDesc@MLDPlay@@QAEKPAUMLDPLAY_SESSIONDESC@@K@Z
    int SetSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, unsigned int a3_size);

    int SendMSResults(char *a2_message);

    int OpenPing_void__PTR_ushort_ushort_ulong_void__PTR_void__PTR(
            void (__stdcall *a2)(unsigned __int16, unsigned __int16, unsigned int, void *),
            void *a3
    ) { return 0; }

    // DKII.EXE import: ordinal=23 name=?GetCurrentMs@MLDPlay@@QAEKXZ
    DWORD GetCurrentMs();

    // DKII.EXE import: ordinal=16 name=?EnableNewPlayers@MLDPlay@@QAEXH@Z
    void EnableNewPlayers(int a2_enabled);

    // DKII.EXE import: ordinal=15 name=?DumpPlayer@MLDPlay@@QAEHK@Z
    int DumpPlayer(unsigned int a2_slot);

    // DKII.EXE import: ordinal=25 name=?GetPlayerDesc@MLDPlay@@QAEKPAUMLDPLAY_PLAYERINFO@@K@Z
    int GetPlayerDesc(MLDPLAY_PLAYERINFO *playerDesc, unsigned int a3_slot_m2_m3);

    unsigned int GetPlayerAddress(unsigned int a2_slot_m2_m3, MyPlayerSubDesc *a3_pAddr, unsigned int *a4_pSize);

    // DKII.EXE import: ordinal=26 name=?GetPlayerInfo@MLDPlay@@QAEHPAUMLDPLAY_PLAYERINFO@@@Z
    int GetPlayerInfo(MLDPLAY_PLAYERINFO *a2_pInfoArr);

    int EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize);

    // DKII.EXE import: ordinal=11 name=?CreateNetworkAddress@MLDPlay@@QAEHPAXK0PAK@Z
    int CreateNetworkAddress(
            DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
            MyDPlayCompoundAddress *a4_outAddr, unsigned int *a5_outSize);

    void AddPacketToMemoryQueue(struct MLDPLAY_SYSTEMQUEUE *a2_queue, void *a3_data, unsigned int a4_copySize, unsigned int a5_dataSize);

    void DestroyMemoryQueue(struct MLDPLAY_SYSTEMQUEUE *a2_queue);

    MLDPLAY_SYSTEMQUEUE_Entry *ReadPacketHeadFromMemoryQueue(MLDPLAY_SYSTEMQUEUE *a2_queue);

    void RemovePacketFromMemoryQueue(MLDPLAY_SYSTEMQUEUE *a2_queue, MLDPLAY_SYSTEMQUEUE_Entry *Block);

    void SetLatency(unsigned int a2_latency);

    void SetServerGrabber(const char *a2_host, uint16_t a3_port);

};
#pragma pack(pop)
static_assert(sizeof(MLDPlay) == 0x1C6);

//  6 ?BFAID_MODEM@@3U_GUID@@A
//  4 ?BFAID_INet@@3U_GUID@@A

}  // namespace net

#endif //FLAME_MLDPLAY_H
