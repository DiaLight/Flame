//
// Created by DiaLight on 09.01.2025.
//

#include "DPlay.h"

using namespace net;

#define print_notDecompiled(prefix) printf(prefix "function %s is not decompiled\n", __FUNCTION__)
#define assert_notDecompiled() do { print_notDecompiled("[FATAL] "); exit(1); } while(false)

int DPlay::Startup(MessageHandlerType handler) {
    assert_notDecompiled();
    return NetworkServiceProvider::Startup(handler);
}

int DPlay::ShutDown() {
    assert_notDecompiled();
    return NetworkServiceProvider::ShutDown();
}

int DPlay::SetupConnection(MyDPlayCompoundAddress *a2_dplayAddr, GUID *a3_guid, void *a4_arg) {
    assert_notDecompiled();
    return 0;
}

int DPlay::EnumerateLocalServices(NetworkServiceProvider::ServiceEnumCallback a2_fun, void *a3_arg) {
//    print_notDecompiled("[WARNING] ");
    return 0;
}

int DPlay::BuildSession(MessageHandlerType handler, GUID *guid, char *a4_outNGLD, DWORD *a5_outPlayers,
                        wchar_t *a6_outGameName, wchar_t *a7_outPlayerName, int a8_totalMaxPlayers, int a9_ignore) {
    assert_notDecompiled();
    return 0;
}

int DPlay::enumLocalApplications(int a2, int a3) {
    assert_notDecompiled();
    return 0;
}

int DPlay::connectLobby(int a2_flags, WCHAR *a3_sessionName, WCHAR *a4_playerName, GUID *a5_guidApplication,
                        wchar_t *a6_address, int a7, int a8_maxPlayers) {
    assert_notDecompiled();
    return 0;
}

int DPlay::CreateSPSession(DWORD *a2_outPlayers, wchar_t *a3_gameName, wchar_t *a4_playerName,
                           MySessionCredentials *a5_cred, int a6_flags) {
    assert_notDecompiled();
    return 0;
}

int DPlay::JoinSPSession(MLDPLAY_SESSIONDESC *a2_desc, DWORD *a3_outPlayerCount, wchar_t *a4_playerName,
                         MySessionCredentials *a5_cred) {
    assert_notDecompiled();
    return 0;
}

int DPlay::DestroySPSession() {
    assert_notDecompiled();
    return 0;
}

int DPlay::EnumerateSessions(DWORD a2_timeout, EnumerateSessionsCallback a3_callback, int a4_flags, void *a5_arg) {
    assert_notDecompiled();
    return 0;
}

int DPlay::getSessionDesc(MLDPLAY_SESSIONDESC *a2_pDesc, DWORD *a3_pSize) {
    assert_notDecompiled();
    return 0;
}

int DPlay::setSessionDesc(MLDPLAY_SESSIONDESC *a2_desc, DWORD a3_size) {
    assert_notDecompiled();
    return 0;
}

int DPlay::DestroySession(unsigned int a2_slot) {
    assert_notDecompiled();
    return 0;
}

void DPlay::EnableNewPlayers(int a2_enabled) {
    assert_notDecompiled();

}

int DPlay::EnumPlayers(GUID *a2_guidInstance, MyPlayerEnumCb a3_callback, int a4_ignored, void *a5_arg) {
    assert_notDecompiled();
    return 0;
}

BOOL DPlay::SendMessage(uint32_t a2_playerId_slot, void *a3_buf, size_t a4_size, int a5_ignored) {
    assert_notDecompiled();
    return FALSE;
}

int DPlay::SendMessageTo(MySocket *a2_dstSock, void *a3_buf, size_t a4_size, int a5_ignored) {
    assert_notDecompiled();
    return 0;
}

PacketHeader *DPlay::ReadSPMessage() {
    assert_notDecompiled();
    return nullptr;
}

void DPlay::setNewHost(MyPacket_E_NewHost *a2_packet) {
    assert_notDecompiled();
}

int DPlay::SendMSResults(const char *a2_message) {
    assert_notDecompiled();
    return 0;
}

unsigned int DPlay::EnumerateNetworkMediums(NetworkServiceProvider::EnumerateNetworkMediumsCallback a2, void *a3) {
    assert_notDecompiled();
    return 0;
}

int DPlay::EnumerateNetworkMediums(void *a2, void *a3_dataBuf, DWORD *a4_pSize) {
    assert_notDecompiled();
    return 0;
}

int DPlay::CreateCompoundAddress(DPCOMPOUNDADDRESSELEMENT *a2_elements, size_t a3_elementCount,
                                 MyDPlayCompoundAddress *a4_outAddr, size_t *a5_outSize) {
    assert_notDecompiled();
    return 0;
}

unsigned int DPlay::__getHiWord(PlayerId playerId) {
    assert_notDecompiled();
    return 0;
}

PacketHeader *DPlay::_handleMessage(PacketHeader *a2_packet, uint8_t a3_handlerTy, int *a4_outSize) {
    assert_notDecompiled();
    return nullptr;
}
