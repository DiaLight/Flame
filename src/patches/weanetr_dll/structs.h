//
// Created by DiaLight on 17.12.2024.
//

#ifndef FLAME_STRUCTS_H
#define FLAME_STRUCTS_H

#include <Windows.h>
#include "MySocket.h"
#include "weanetr_memory.h"
#include <cstdint>

namespace net {

#define net_AllPlayers ((uint16_t) -1)  // 0xFFFF
#define net_HostPlayer ((uint16_t) -2)  // 0xFFFE
#define net_CurrentPlayer ((uint16_t) -3)  // 0xFFFD
#define net_AllPlayers2 ((uint16_t) -4)  // 0xFFFC

struct PlayerId {
    union {
        struct {
            uint16_t playerIdx;
            int16_t slotIdx;
        };
        uint32_t value;
    };

    bool operator==(const PlayerId &rhs) const { return value == rhs.value; }
    bool operator!=(const PlayerId &rhs) const { return !(rhs == *this); }

    bool operator==(const uint16_t &rhs) const { return value == rhs; }
};
static_assert(sizeof(PlayerId) == 4);


#pragma pack(push, 1)
struct MyPlayerSubDesc {
    DWORD f0_ipv4;
    u_short f4_portBe;
    GUID f6_guidPlayer;
    __int16 f16__sdUnk1;
    char f18__sdUnk2;
};
#pragma pack(pop)
static_assert(sizeof(MyPlayerSubDesc) == 0x19);

#pragma pack(push, 1)
struct MLDPLAY_PLAYERINFO {
    BYTE f0_flags;
    DWORD dword_1;
    BYTE f5_slotNo;
    wchar_t f6_shortName[16];  // unused?
    PlayerId f26_playerId_slot;

    [[nodiscard]] inline bool isHost() const {
        return (this->f0_flags & 0xF0) != 0;
    }

    [[nodiscard]] inline bool isJoined() const {
        return (this->f0_flags & 0x0F) != 0;
    }
};
#pragma pack(pop)
static_assert(sizeof(MLDPLAY_PLAYERINFO) == 0x2A);

#pragma pack(push, 1)
struct MyPlayerCbData {  // is equal to MLDPLAY_PLAYERINFO ???
    BYTE f0_flags;
    DWORD field_1;
    BYTE f5_slotNo;
    wchar_t f6_shortName[16];
    PlayerId f26_playerId_slot;
};
#pragma pack(pop)
static_assert(sizeof(MyPlayerCbData) == 0x2A);

struct MLDPLAY_SESSIONDESC {
    int dk2Version = 0;
    GUID guidInstance = {0};
    GUID guidApplication = {0};
    int totalMaxPlayers = 0;
    int currentPlayers = 0;
    BYTE f2C[16] = {0};
    int flags = 0;  // 0x200: has password
    int mapNameLen_mapPlayersCount = 0;
    int mapNameHash = 0;
    int fileHashsum = 0;
    int cred_2C = 0;
    MySocket sock;
    char f5A[10] = {0};
    wchar_t gameName[32] = {0};
};
static_assert(sizeof(MLDPLAY_SESSIONDESC) == 0xA4);


struct ListEntry_SessionDesc {
    MLDPLAY_SESSIONDESC f0_desc;
    DWORD fA4_timeMs;
    ListEntry_SessionDesc *fA8_next;
};
static_assert(sizeof(ListEntry_SessionDesc) == 0xAC);


#pragma pack(push, 1)
struct MyCurPlayerInfo {
    int flags = 0;
    PlayerId playerId = {0};
    int playersSlot = 0;
    unsigned int guaranteedScheduledCount = 0;
    BYTE f10_arr[28] = {0};
    char f2C = 0;

    [[nodiscard]] inline bool isHost() const {
        return (this->flags & 1) != 0;
    }

    [[nodiscard]] inline bool isConnectedToSession() const {
        return (this->flags & 2) != 0;
    }

};
#pragma pack(pop)
static_assert(sizeof(MyCurPlayerInfo) == 0x2D);


struct MLDPLAY_SYSTEMQUEUE_Entry {
    MLDPLAY_SYSTEMQUEUE_Entry *prev;
    MLDPLAY_SYSTEMQUEUE_Entry *next;
    int _slotPacketCount;
    int dataSize;
    void *pData;
};
static_assert(sizeof(MLDPLAY_SYSTEMQUEUE_Entry) == 0x14);


struct MLDPLAY_SYSTEMQUEUE {
    MLDPLAY_SYSTEMQUEUE_Entry *first = NULL;
    MLDPLAY_SYSTEMQUEUE_Entry *last = NULL;


    static MLDPLAY_SYSTEMQUEUE_Entry *getFirst(MLDPLAY_SYSTEMQUEUE *self) {
        if ( !self ) return NULL;
        return self->first;
    }

    static MLDPLAY_SYSTEMQUEUE_Entry *addEntry(MLDPLAY_SYSTEMQUEUE *self, const void *a2_data, unsigned int a3_copySize, int a4_dataSize) {
        MLDPLAY_SYSTEMQUEUE_Entry *newEntry = (MLDPLAY_SYSTEMQUEUE_Entry *) net::_malloc(sizeof(MLDPLAY_SYSTEMQUEUE_Entry) + a4_dataSize);
        if ( !newEntry ) return NULL;
        void *pData = (void *) (newEntry + 1);
        memcpy(pData, a2_data, a3_copySize);
        newEntry->pData = pData;
        newEntry->dataSize = a4_dataSize;
        newEntry->next = NULL;
        if (self->last) {
            newEntry->prev = self->last;
            self->last->next = newEntry;
            self->last = newEntry;
            return newEntry;
        }
        newEntry->prev = NULL;
        self->first = newEntry;
        self->last = newEntry;
        return newEntry;
    }

    static void removeEntry(MLDPLAY_SYSTEMQUEUE *self, MLDPLAY_SYSTEMQUEUE_Entry *entry) {
        int hasNoPrev = 0;
        if ( entry->prev )
            entry->prev->next = entry->next;
        else
            hasNoPrev = 1;

        int hasNoNext = 0;
        if ( entry->next )
            entry->next->prev = entry->prev;
        else
            hasNoNext = 1;

        if ( hasNoPrev ) self->first = entry->next;

        if ( hasNoNext ) {
            if (hasNoPrev) {
                self->last = NULL;
            } else {
                self->last = entry->prev;
            }
        }
        net::_free(entry);
    }

    static void release(MLDPLAY_SYSTEMQUEUE *queue) {
        if (!queue) return;
        MLDPLAY_SYSTEMQUEUE_Entry *cur = queue->first;
        if (!queue->first) return;
        do {
            MLDPLAY_SYSTEMQUEUE_Entry *entry = cur;
            cur = cur->next;
            net::_free(entry);
        } while ( cur );
        queue->first = NULL;
        queue->last = NULL;
    }

};
static_assert(sizeof(MLDPLAY_SYSTEMQUEUE) == 0x8);


struct MySessionCredentials {
    int f0_credentialParameterSize;
    int f4_dk2Version;
    int field_8;
    int field_C;
    int f10_totalMaxPlayers;
    int f14__totalMaxPlayers2;
    int field_18;
    const wchar_t *f1C_password;
    int f20_mapNameLen_mapPlayersCount;
    int f24_mapNameHash;
    int f28_fileHashsum;
    int field_2C;
};
static_assert(sizeof(MySessionCredentials) == 0x30);


struct MyAddrStruc {
    char f0_boundip[20];
    int f14_ipv4;
};
static_assert(sizeof(MyAddrStruc) == 0x18);

#pragma pack(push, 1)
struct MyAddr {
    wchar_t *f0_pAddr;
    size_t f4_size;
    uint16_t f8_port;
};
#pragma pack(pop)
static_assert(sizeof(MyAddr) == 0xA);

#pragma pack(push, 1)
struct MyPlayerDesc {
    wchar_t f0_playername[16];
    PlayerId f20_playerId_slot;
    int field_24;
    int field_28;
    int f2C_packet_D_Guaranteed_sendScheduled_count;
    unsigned int f30_receivedScheduled_count;
    BYTE flags;  // 0x10: is host  0x01: player joined
    uint8_t f35_slotNo;
    MyPlayerSubDesc f36_subDesc;

    [[nodiscard]] inline bool isHost() const {
        return (this->flags & 0xF0) != 0;
    }

    [[nodiscard]] inline bool isJoined() const {
        return (this->flags & 0x0F) != 0;
    }
};
#pragma pack(pop)
static_assert(sizeof(MyPlayerDesc) == 0x4F);


#pragma pack(push, 1)
struct MyDPlayCompoundAddress {
    char f0_signature[2];
    GUID f2_guid_BFSPGUID_TCPIP;
    MyAddr f12_addr;
    BYTE gap_1C[4];
    __int16 word_20;
};
#pragma pack(pop)
static_assert(sizeof(MyDPlayCompoundAddress) == 0x22);

#pragma pack(push, 1)
struct MyLocalServiceAddr {
    char f0_signature[2];
    GUID f2_guid;
    MyAddr f12_addr;
    BYTE gap_1C[6];
    wchar_t f22_addr[];
};
#pragma pack(pop)
static_assert(sizeof(MyLocalServiceAddr) == 0x22);

#pragma pack(push, 1)
struct MyLocalService {
    GUID f0_guid;
    DWORD f10_count;
    size_t f14_addr_size;
    wchar_t *f18_pName;
    MyLocalService *f1C_next;
    MyLocalServiceAddr *f20_addr;
    GUID *f24_pGuid;
    wchar_t f28_name[];
};
#pragma pack(pop)
static_assert(sizeof(MyLocalService) == 0x28);


#pragma pack(push, 1)
struct MyReceivedHeader {
    int f0__guaranteedIdx;
    int f4__recv_sendScheduled_idx;
    PlayerId f8_playerId_slot;
    int fC_blocksChunk_startIdx;
    int f10_maxPartsCount;
    size_t f14_partSize;
    size_t f18_totalSize;
    char f1C_recvdArr[8];
    BYTE f24_data;
};
#pragma pack(pop)
static_assert(sizeof(MyReceivedHeader) == 0x25);


struct DeliverStatus {
    PlayerId playerId_slot;
    int status;
};
static_assert(sizeof(DeliverStatus) == 8);

struct DeliverStatusEntry {
  DeliverStatusEntry *next;
  DeliverStatus item;
};
static_assert(sizeof(DeliverStatusEntry) == 0xC);


struct MyMsgLog {
    DWORD f0_numPlayersToSend;
    DWORD f4_counter2;
    DWORD f8_fullySentData;
    DeliverStatus *fC_statusArr;
};
static_assert(sizeof(MyMsgLog) == 0x10);


struct MyGuarateedData {
    int f0_guaranteedIdx;
    // 0: part failed
    // 1: part success
    // 3: failed
    int f4_type;
    MyMsgLog *f8_pMsgLog;
};
static_assert(sizeof(MyGuarateedData) == 0xC);


struct MyGuarateedData_MsgLog {
    MyGuarateedData hdr;
    MyMsgLog log;
};
static_assert(sizeof(MyGuarateedData_MsgLog) == 0x1C);


struct MyDeliverHeader {
    DWORD f0_guaranteedCount;
    DWORD f4_playerListIdx_m1_m2;
    DWORD f8_flags;
    DWORD fC_sendScheduled_idx;
    DWORD f10_numPlayersToSend;
    DWORD f14_counter2;
    DWORD f18_fullySentData;
    DWORD f1C_size;
    DWORD f20__receivedOffs;
    DWORD field_24;
    DWORD field_28;
    DWORD field_2C;
    DWORD field_30;
    DWORD field_34;
    DeliverStatusEntry *f38_statusList;
    MLDPLAY_SYSTEMQUEUE f3C_packetsQueue_perPlayer;
    void *f44_fullDataToSend;

    static int __stdcall getStatusCount(MyDeliverHeader *header) {
        int count = 0;
        for (DeliverStatusEntry *cur = header->f38_statusList; cur; cur = cur->next ) ++count;
        return count;
    }

    static void clearList(MyDeliverHeader *header) {
        DeliverStatusEntry *cur = header->f38_statusList;
        while ( cur ) {
            DeliverStatusEntry *entry = cur;
            cur = cur->next;
            net::_free(entry);
        }
    }
    static void addStatus(MyDeliverHeader *header, PlayerId a2_playerId_slot, int a3_status) {
        DeliverStatusEntry *newItem;
        if (!header->f38_statusList) {
            newItem = (DeliverStatusEntry *) net::_malloc(sizeof(DeliverStatusEntry));
            header->f38_statusList = newItem;
        } else {
            DeliverStatusEntry *lastItem;
            for(auto *e = header->f38_statusList; e; e = e->next) lastItem = e;
            newItem = (DeliverStatusEntry *) net::_malloc(sizeof(DeliverStatusEntry));
            lastItem->next = newItem;
        }
        if(!newItem) return;
        newItem->next = NULL;
        newItem->item.playerId_slot = a2_playerId_slot;
        newItem->item.status = a3_status;
    }

};
static_assert(sizeof(MyDeliverHeader) == 0x48);

typedef void (* MessageHandlerType)(int playersSlot, void *msg, int msgSz, int msgTy, void *arg);
typedef void (__stdcall *EnumerateSessionsCallback)(MLDPLAY_SESSIONDESC *, void *);
typedef void (__stdcall *MyPlayerEnumCb)(MyPlayerCbData *, DWORD);
typedef void (__stdcall *EnumerateServicesCallback)(MyLocalService *service, wchar_t *name, GUID *guid, DWORD idx, void *arg);

}  // namespace net

#endif //FLAME_STRUCTS_H
