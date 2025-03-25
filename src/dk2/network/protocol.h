//
// Created by DiaLight on 03.02.2025.
//

#ifndef FLAME_DK2_PROTOCOL_H
#define FLAME_DK2_PROTOCOL_H

#include <cstdint>
#include "dk2/network/protocol/DataMessage_1.h"
#include "dk2/network/protocol/DataMessage_3.h"
#include "dk2/network/protocol/NetMessage_65.h"
#include <cstddef>


namespace dk2 {

#pragma pack(push, 1)
    struct DK2PacketHeader {
        uint8_t packetId;
    };
#pragma pack(pop)
    static_assert(sizeof(DK2PacketHeader) == 0x1);


#pragma pack(push, 1)
    struct DK2Packet_1_ActionArr : public DK2PacketHeader {
        // send 00523565  collectActions_part3
        // send 005235D6  collectActions_part3
        // send 00524AAC  resendMissingActions
        // send 00524B1D  resendMissingActions
        // read 0052432E  // CNetworkCommunication data

        constexpr static uint8_t ID = 1;

        dk2::DataMessage_1 data;

        [[nodiscard]] int size() const {
            uint8_t count = this->data.actionArr_count;
            if (count == 0xFF ) count = 0;
            return offsetof(DK2Packet_1_ActionArr, data.actionArr) + sizeof(GameAction) * count - sizeof(DK2PacketHeader);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_1_ActionArr) == 0x130);


#pragma pack(push, 1)
    struct DK2Packet_2_GameAction : public DK2PacketHeader {
        // send 00522F3D
        // read 0052436A  // CNetworkCommunication data

        constexpr static uint8_t ID = 2;

        GameAction act;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_2_GameAction);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_2_GameAction) == 0x13);


#pragma pack(push, 1)
    struct DK2Packet_3_ResendActionsRequest : public DK2PacketHeader {
        // send 00523892
        // read 0052437E  // CNetworkCommunication data

        constexpr static uint8_t ID = 3;

        dk2::DataMessage_3 times;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_3_ResendActionsRequest);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_3_ResendActionsRequest) == 0x9);


#pragma pack(push, 1)
    struct DK2Packet_B_UploadTrackPing : public DK2PacketHeader {  // data
        // host -> broadcast to all clients  in a loop while uploading
        // send 0052513C
        // read 005243BA  // CNetworkCommunication data

        constexpr static uint8_t ID = 0xB;

        int f0_save2else1;
        int f4_slotMask;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_B_UploadTrackPing);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_B_UploadTrackPing) == 0x9);


#pragma pack(push, 1)
    struct DK2Packet_C_UploadTrackPong : public DK2PacketHeader {  // data
        // client -> host  as answer to B or on upload track start
        // send 005250D0
        // read 00524461  // CNetworkCommunication data

        constexpr static uint8_t ID = 0xC;

        int f0_save2else1;
        int f4_4343;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_C_UploadTrackPong);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_C_UploadTrackPong) == 0x9);


#pragma pack(push, 1)
    struct DK2Packet_15_WorldChecksum : public DK2PacketHeader {
        // client -> host
        // send 00525010
        // read 005242CF  // CNetworkCommunication data

        constexpr static uint8_t ID = 0x15;

        int f0_gameTick;
        int f4_checksum;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_15_WorldChecksum);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_15_WorldChecksum) == 0x9);


#pragma pack(push, 1)
    struct DK2Packet_1F_LoadLevelStatus : public DK2PacketHeader {
        // send 00525070
        // read 00524290  // CNetworkCommunication data

        constexpr static uint8_t ID = 0x1F;

        int f0_zero;
        int f4_loadStatus;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_1F_LoadLevelStatus);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_1F_LoadLevelStatus) == 0x9);


#pragma pack(push, 1)
    struct DK2Packet_20_IAmAlive : public DK2PacketHeader {
        // client -> host
        // if ( notHost && (nowMs - this->fFDC8_lastSendWorldPacketTimeMs) > 1000 )
        //     this->super.f2C_sendData_20(this);
        // send 00524FAE

        constexpr static uint8_t ID = 0x20;  // ' '

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_20_IAmAlive);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_20_IAmAlive) == 0x1);


#pragma pack(push, 1)
    struct DK2Packet_29_Ping : public DK2PacketHeader {
        // host -> all clients
        // send 005233CA
        // read 005244D0  // CNetworkCommunication data

        constexpr static uint8_t ID = 0x29;  // ')'

        int gameTick;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_29_Ping);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_29_Ping) == 0x5);


#pragma pack(push, 1)
    struct DK2Packet_2A_Pong : public DK2PacketHeader {
        // client -> host
        // send 00524520
        // read 00524568  // CNetworkCommunication data

        constexpr static uint8_t ID = 0x2A;  // '*'

        int gameTick;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_2A_Pong);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_2A_Pong) == 0x5);


#pragma pack(push, 1)
    struct DK2Packet_63_GuaranteedDataSuccess : public DK2PacketHeader {  // guaranteed
        // send 005278D2
        // read 0052823B  // CNetworkComponent guaranteedData

        constexpr static uint8_t ID = 0x63;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_63_GuaranteedDataSuccess);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_63_GuaranteedDataSuccess) == 0x1);




#pragma pack(push, 1)
    struct DK2Packet_65_SyncTimingRequest : public DK2PacketHeader {
        // any -> any
        // send 00543D62
        // read 005440D9  // CFrontEndComponent data

        constexpr static uint8_t ID = 0x65;  // 'e'

        int id;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_65_SyncTimingRequest);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_65_SyncTimingRequest) == 0x5);
    static_assert(sizeof(DK2Packet_65_SyncTimingRequest) == sizeof(dk2::NetMessage_65));


#pragma pack(push, 1)
    struct DK2Packet_66_UpdateTimings : public DK2PacketHeader {
        // client -> client
        // send 00544134
        // read 005440B6  // CFrontEndComponent data

        constexpr static uint8_t ID = 0x66;  // 'f'

        int id;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_66_UpdateTimings);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_66_UpdateTimings) == 0x5);


#pragma pack(push, 1)
    struct DK2Packet_67_AllTimings : public DK2PacketHeader {
        // host -> client
        // send 005440E3
        // read 00544164  // CFrontEndComponent data

        constexpr static uint8_t ID = 0x67;  // 'g'

        int totalTimeMs_shr4[8];

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_67_AllTimings);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_67_AllTimings) == 0x21);


//    struct DK2Packet_68_PlayerBuf : public DK2PacketHeader {
//        // send 00544574
//        // read 0054422A  // CFrontEndComponent data
//
//        constexpr static uint8_t ID = 0x68;  // 'h'
//
//        [[nodiscard]] int size() const {
//        }
//    };


//    struct DK2Packet_69_SelectedMapName : public DK2PacketHeader {
//        // send 00543A7C
//        // read 00544186  // CFrontEndComponent data
//
//        constexpr static uint8_t ID = 0x69;  // 'i'
//
//        wchar_t name[];
//
//        [[nodiscard]] int size() const {
//        }
//    };


//    struct DK2Packet_6B_AllPlayersBuf : public DK2PacketHeader {
//        // send 0054552F
//        // read 005442D4  // CFrontEndComponent data
//
//        constexpr static uint8_t ID = 0x6B;  // 'k'
//
//        [[nodiscard]] int size() const {
//        }
//    };


#pragma pack(push, 1)
    struct DK2Packet_6E_PlayerKicked : public DK2PacketHeader {
        // send 005455C3
        // send 00545772
        // read 0054435E  // CFrontEndComponent data

        constexpr static uint8_t ID = 0x6E;  // 'n'

        int playerId;

        [[nodiscard]] int size() const {
            return sizeof(DK2Packet_6E_PlayerKicked);
        }
    };
#pragma pack(pop)
    static_assert(sizeof(DK2Packet_6E_PlayerKicked) == 0x5);


//    struct DK2Packet_6F_CurrentLobbyStatus : public DK2PacketHeader {
//        // send 0054906D
//        // read 005443A0  // CFrontEndComponent data
//
//        constexpr static uint8_t ID = 0x6F;  // 'o'
//
//        [[nodiscard]] int size() const {
//        }
//    };


//    struct DK2Packet_C7_GameStartInfo : public DK2PacketHeader {  // guaranteed
//        // send 005436B9
//        // read 00543206  // CFrontEndComponent guaranteedData
//
//        constexpr static uint8_t ID = 0xC7;
//
//        [[nodiscard]] int size() const {
//        }
//    };


}


#endif //FLAME_DK2_PROTOCOL_H
