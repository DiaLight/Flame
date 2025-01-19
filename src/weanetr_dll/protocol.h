//
// Created by DiaLight on 17.12.2024.
//

#ifndef FLAME_PROTOCOL_H
#define FLAME_PROTOCOL_H

#include <Windows.h>
#include "structs.h"

namespace net {

struct PacketHeader {
    constexpr static uint8_t MAGIC = 0xBF;  // BullFrog

    BYTE signature;
    BYTE packetTy;
    BYTE f2;
    BYTE f3;
    uint16_t playersSlot;
    uint16_t playerListIdx_m1_m2;  // can be: net_AllPlayers, net_HostPlayer
    int f8_messageSize;
};
static_assert(sizeof(PacketHeader) == 0xC);


#pragma pack(push, 1)
struct MyPacket_1_Create {
    constexpr static uint8_t ID = 1;

    // send[sched]=1000B090  read1=1000BBFB  read2=1000C295
    PacketHeader f0_hdr;
    int fC_flags;
    int f10_ackPacketId;
    int f14_totalMaxPlayers;
    int f18_currentPlayers;
    char f1C_ign[16];
    GUID f2C_guidApplication;
    GUID f3C_guidInstance;
    MyPlayerDesc f4C_playerDesc;
};
#pragma pack(pop)
static_assert(sizeof(MyPacket_1_Create) == 0x9B);


struct MyPacket_2_SessionLost {
    constexpr static uint8_t ID = 2;

    // SessionLost read=1000C4F3
    PacketHeader f0_hdr;
};  // fixme: unknown size


struct MyPacket_3_Data {
    constexpr static uint8_t ID = 3;

    // 0x03: [lobby]  send=(0055AC20 WeaNetR_sendDataMessage)
    PacketHeader f0_hdr;
    uint8_t fC_data[];
};  // variable size

struct MyPacket_4_ChatMessage {
    constexpr static uint8_t ID = 4;

    // [lobby] send=1000CB20  read=1000C502
    PacketHeader f0_hdr;
    wchar_t fC_message[];
};  // variable size


struct MyPacket_5_SessionRequest {
    constexpr static uint8_t ID = 5;

    PacketHeader f0_hdr;
    GUID fC_guidApplication;
};
static_assert(sizeof(MyPacket_5_SessionRequest) == 0x1C);

struct MyPacket_6_sessionDesc {
    constexpr static uint8_t ID = 6;

    PacketHeader f0_hdr;
    MLDPLAY_SESSIONDESC fC_desc;
};
static_assert(sizeof(MyPacket_6_sessionDesc) == 0xB0);

struct MyPacket_7_Join {
    constexpr static uint8_t ID = 7;

    PacketHeader f0_hdr;
    int fC_flags;
    GUID f10_guidApplication;
    GUID f20_guidInstance;
    GUID f30_guidPlayer;
    wchar_t f40_playerName[16];
    wchar_t f60_password[32];
};
static_assert(sizeof(MyPacket_7_Join) == 0xA0);

struct MyPacket_8_PlayerAdded {
    constexpr static uint8_t ID = 8;

    PacketHeader f0_hdr;
    int fC_flags_ign;
    GUID f10_guidApplication;
    GUID f20_guidInstance;
    GUID f30_guidPlayer;
    PlayerId f40_playerId;
    PlayerId f44_hostPlayerId;
    DWORD f48_totalMaxPlayers;
    DWORD f4C_currentPlayers;
    char f50_ign[16];
};
static_assert(sizeof(MyPacket_8_PlayerAdded) == 0x60);

struct MyPacket_9_PlayerLeave {
    constexpr static uint8_t ID = 9;

    PacketHeader f0_hdr;
    int fC_flags;
    DWORD f10_ackPacketId;
    int f14_totalMaxPlayers;
    int f18_currentPlayers;
    char f1C_ign[16];
    GUID f2C_guidApplication;
    GUID f3C_guidInstance;
    GUID f4C_guidPlayer;
    PlayerId f5C_playerId;
};
static_assert(sizeof(MyPacket_9_PlayerLeave) == 0x60);

struct MyPacket_A_DestroyPlayer {
    constexpr static uint8_t ID = 0xA;

    PacketHeader f0_hdr;
    int fC_flags;
    int f10_ackPacketId;
    int f14_totalMaxPlayers;
    int f18_currentPlayers;
    char f1C_ign[16];
    GUID f2C_guidApplication;
    GUID f3C_guidInstance;
    GUID f4C_guidPlayer;
    PlayerId f5C_playerId;
};
static_assert(sizeof(MyPacket_A_DestroyPlayer) == 0x60);

#pragma pack(push, 1)
struct MyPacket_B_PlayerList {
    constexpr static uint8_t ID = 0xB;

    PacketHeader f0_hdr;
    DWORD fC_ackPacketId;
    PlayerId f10_playerId;
    int f14_totalMaxPlayers;
    int f18_currentPlayers;
    BYTE f1C_ign[16];
    DWORD f2C_playerDescCount;
    MyPlayerDesc f30_MyPlayerDesc_arr[5];
};
#pragma pack(pop)
static_assert(sizeof(MyPacket_B_PlayerList) == 0x1BB);

struct MyPacket_C_HandledPackets {
    constexpr static uint8_t ID = 0xC;

    PacketHeader hdr;
    PlayerId playerId;
    int AckPacketsCountArr[50];
};
static_assert(sizeof(MyPacket_C_HandledPackets) == 0xD8);

struct MyPacket_D_Guaranteed {
    constexpr static uint8_t ID = 0xD;

    PacketHeader f0_hdr;
    int fC__timeout;
    DWORD f10_deltaTiming;
    DWORD f14_lastReadTime;
    DWORD f18_startReadTime;
    PlayerId f1C_playerId;
    PlayerId f20_playerId_slot;
    unsigned int f24_guaranteedCount;
    int f28_sendScheduled_idx;
    size_t f2C_totalSize;
    size_t f30_partSize;
    int f34_blocksChunk_startIdx;
    unsigned int f38_transferedPartsCount_max;
    char f3C_partsReceived_arr[8];
    size_t f44_totalPartsCount;
    DWORD f48_blockIdx;
};
static_assert(sizeof(MyPacket_D_Guaranteed) == 0x4C);

#pragma pack(push, 1)
struct MyPacket_E_NewHost {
    constexpr static uint8_t ID = 0xE;

    PacketHeader f0_hdr;
    int fC_flags;
    DWORD f10_ackPacketId;
    int field_14;
    int field_18;
    int f1C_totalMaxPlayers;
    int f20_currentPlayers;
    char field_24[16];
    GUID f34_guidApplication;
    GUID f44_guidInstance;
    wchar_t f54_playerName[16];
    PlayerId f74_playerId;
    int field_78;
    int field_7C;
    char field_80;
    BYTE field_81;
    BYTE field_82[6];
    char f88__17;
    BYTE f89_playerSlot;
    MyPlayerSubDesc f8A_subDesc;
    char field_A3[16];
};
#pragma pack(pop)
static_assert(sizeof(MyPacket_E_NewHost) == 0xB3);


#pragma pack(push, 1)
struct MyPacket_F_MigrateHost {
    constexpr static uint8_t ID = 0xF;

    // send=100026A4  read=
    PacketHeader f0_hdr;
    int field_C;
    int f10__slotPacketCount;
    int f14_sessionFlags;
    PlayerId f18_curPlayerId;
    int f1C_totalMaxPlayers;
    int f20_currentPlayers;
    int field_24;
    int field_28;
    int field_2C;
    int field_30;
    GUID f34_guidApplication;
    GUID f44_guidInstance;
    wchar_t f54_playername[16];
    PlayerId f74_playerId_slot;
    char f78_gap[16];
    char f88__17;
    char f89_slotNo;
    MyPlayerSubDesc f36_subDesc;
    PlayerId fA3_last_playerId_slot;
    char fA7_gap[11];
    char field_B2;
};
#pragma pack(pop)
static_assert(sizeof(MyPacket_F_MigrateHost) == 0xB3);


struct MyPacket_10_GuaranteedProgress {
    constexpr static uint8_t ID = 0x10;

    // [lobby] GuaranteedProgress  send=1000D901  read=1000C530
    PacketHeader f0_hdr;
    PlayerId fC_playerId_slot;
    PlayerId f10_playerId;
    DWORD f14_guaranteedCount;
    DWORD f18_sendScheduled_idx;
    DWORD f1C_blocksChunk_startIdx;
    DWORD f20_maxPartsCount;
    char f24_recvdArr[8];
};
static_assert(sizeof(MyPacket_10_GuaranteedProgress) == 0x2C);

struct ScheduledPacket {
    ScheduledPacket *f0_next;
    DWORD f4_ackPacketId;
    int f8_slotMask;
    int fC__0;
    int f10__60000;
    int f14_timeSendDelta;
    int f18_lastSendTime;
    int f1C_addedTime;
    int f20_packetSize;
    PacketHeader *f24_pPacketStart;
};
static_assert(sizeof(ScheduledPacket) == 0x28);

#pragma pack(push, 1)
struct ScheduledPacket_B_PlayerList : public ScheduledPacket {
    MyPacket_B_PlayerList f28_packet;
};
#pragma pack(pop)
static_assert(sizeof(ScheduledPacket_B_PlayerList) == 0x1E3);

}  // namespace net

#endif //FLAME_PROTOCOL_H
