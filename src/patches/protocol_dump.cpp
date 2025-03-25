//
// Created by DiaLight on 11.03.2025.
//

#include "protocol_dump.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <chrono>
#include "dk2/network/protocol.h"
#include "dk2/network/MyGuaranteedData.h"
#include "tools/command_line.h"
#include "dk2_globals.h"
#include "tools/hexdump2.hpp"


#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec
#define fmtHex16(val) std::hex << std::setw(4) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << (val) << std::dec

namespace {

    void printNow(std::ostream &os) {
        auto now = std::chrono::system_clock::now();
        auto ms = duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
        auto t = std::chrono::system_clock::to_time_t(now);
        std::tm tm = *std::localtime(&t);
        os << std::put_time(&tm, "%H:%M:%S");
        os << '.' << std::setfill('0') << std::setw(3) << ms.count();
    }
    struct dk2now {
        explicit dk2now() {}
        friend std::ostream& operator<<(std::ostream& os, const dk2now& mp) {
            printNow(os);
            return os;
        }
    };

    void printSlot(std::ostream &os, size_t slot) {
        // dst slot
#define net_AllPlayers ((uint16_t) -1)  // 0xFFFF
#define net_HostPlayer ((uint16_t) -2)  // 0xFFFE
#define net_CurrentPlayer ((uint16_t) -3)  // 0xFFFD
#define net_AllPlayers2 ((uint16_t) -4)  // 0xFFFC
        if(slot == net_AllPlayers) {
            os << "All";
        } else if(slot == net_HostPlayer) {
            os << "Host";
        } else if(slot == net_CurrentPlayer) {
            os << "Cur";
        } else if(slot == net_AllPlayers2) {
            os << "All2";
        } else {
//            os << std::setfill(' ') << std::setw(4) << std::left << slot << std::right;
            os << slot;
        }
    }
    struct dk2slot {
        int slot;
        explicit dk2slot(size_t slot) : slot(slot) {}
        friend std::ostream& operator<<(std::ostream& os, const dk2slot& mp) {
            printSlot(os, mp.slot);
            return os;
        }
    };

    void dk2Proto_printPacket(std::ostream &os, uint8_t ty, void *data, size_t size) {
        os << fmtHex8(ty) << ":" << std::setfill(' ') << std::setw(16) << std::left;
        switch (ty) {
            case dk2::DK2Packet_1_ActionArr::ID:
                os << "ActionArr";
                break;
            case dk2::DK2Packet_2_GameAction::ID:
                os << "GameAction";
                break;
            case dk2::DK2Packet_B_UploadTrackPing::ID:
                os << "UploadTrackPing";
                break;
            case dk2::DK2Packet_C_UploadTrackPong::ID:
                os << "UploadTrackPong";
                break;
            case dk2::DK2Packet_15_WorldChecksum::ID:
                os << "WorldChecksum";
                break;
            case dk2::DK2Packet_1F_LoadLevelStatus::ID:
                os << "LoadLevelStatus";
                break;
            case dk2::DK2Packet_20_IAmAlive::ID:
                os << "IAmAlive";
                break;
            case dk2::DK2Packet_65_SyncTimingRequest::ID:
                os << "SyncTimingReq";
                break;
            case dk2::DK2Packet_66_UpdateTimings::ID:
                os << "UpdateTimings";
                break;
            case dk2::DK2Packet_67_AllTimings::ID:
                os << "AllTimings";
                break;
            case 0x68:
                os << "PlayerBuf";
                break;
            case 0x69:
                os << "SelectedMapName";
                break;
            case 0x6B:
                os << "AllPlayersBuf";
                break;
            case 0x6F:
                os << "CurrentLobbyStatus";
                break;
            case 0xC7:
                os << "GameStartInfo";
                break;
            default:
                os << std::right << fmtHex8(ty);
                for (int i = 0; i < 14; ++i) os << " ";
                break;
        }
        os << std::right;
        os << " ";
        if(size != -1) {
            os << "sz=" << std::setw(4) << std::setfill(' ') << size << " ";
        }
    }

    bool dk2Proto_hasPlayerBuf(void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        int playerType = pos[size - 5] & 7;
        return playerType != 0;
    }
    uint8_t *dk2Proto_printRelations(std::ostream &os, uint8_t *pos) {
        uint8_t relations1Mask = *pos++;
        uint8_t relations2Mask = *pos++;
        os << "rels=[";
        for (int i = 0; i < 8; ++i) {
            if(i != 0) os << ",";
            bool has1 = ((1 << i) & relations1Mask) != 0;
            os << (has1 ? "1" : "0");
            os << ":";
            bool has2 = ((1 << i) & relations2Mask) != 0;
            os << (has2 ? "1" : "0");
        }
        os << "] ";
        return pos;
    }
    bool dk2Proto_printPlayerBuf(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        int playerType = pos[size - 5] & 7;
#define PLAYER_TYPE_Computer 1
#define PLAYER_TYPE_Human 2
#define PLAYER_TYPE_Unk1 3
        if (playerType == PLAYER_TYPE_Human || playerType == PLAYER_TYPE_Unk1) {
            uint16_t *wpos = (uint16_t *) data;
            os << "name=" << '"';
            while (true) {
                uint16_t ch = *wpos++;
                if(ch == 0) break;
                if(0x20 <= ch && ch < 0x7F) {
                    os << (char) ch;
                } else {
                    os << "\\x" << fmtHex16(ch);
                }
                if((ch & 0xFF) == 0xFF) break;
            }
            os << '"' << " ";
            pos = (uint8_t *) wpos;
        } else if(playerType == PLAYER_TYPE_Computer) {
            auto *ipos = (uint32_t *) data;
            uint32_t aiid = *ipos++;  // [0-8]
            switch (aiid) {
                case 0: os << "ai=Master "; break;
                case 1: os << "ai=Conqueror "; break;
                case 2: os << "ai=Psychotic "; break;
                case 3: os << "ai=Stalwart "; break;
                case 4: os << "ai=Greyman "; break;
                case 5: os << "ai=Idiot "; break;
                case 6: os << "ai=Guardian "; break;
                case 7: os << "ai=ThickSkinned "; break;
                case 8: os << "ai=Paranoid "; break;
                default: os << "ai=" << fmtHex32(aiid) << " "; break;
            }
            pos = (uint8_t *) ipos;
        } else {
            os << "unk pl_ty=" << playerType;
            return false;
        }
        pos = dk2Proto_printRelations(os, pos);
        auto totalTimeMs_shr4 = *(uint32_t *) pos;
        pos += sizeof(totalTimeMs_shr4);
        os << "totalTimeMs_shr4=" << fmtHex32(totalTimeMs_shr4) << " ";
        auto physMem_mb = *(uint16_t *) pos;
        pos += sizeof(physMem_mb);
        os << "physMem=" << physMem_mb << "MB ";
        auto flags = *pos++;
        playerType = flags & 7;
        switch(playerType) {
            case PLAYER_TYPE_Computer: os << "ty=Computer "; break;
            case PLAYER_TYPE_Human: os << "ty=Human "; break;
            default: os << "ty=Unk" << playerType << " "; break;
        }
        os << "flags=";
        if((flags & 0x10) != 0) os << ",_isAi";
        if((flags & 0x40) != 0) os << ",mapPresent";
        if((flags & 0x80) != 0) os << ",_isHost";
        if((flags & 0x20) != 0) os << ",UNK1";  // must be zero
        if((flags & 0x08) != 0) os << ",UNK2";  // must be zero
        os << " ";

//        os << "flags=" << fmtHex8(flags) << " ";
//         player:   0x32 00 11 0 010
//         computer: 0x19 00 01 1 001
//
//         playerType:    .. . . . xxx
//         _isAi:         .. . . x ...
//         mapPresent:    .. . x . ...
//         _isHost:       xx x . . ...
//        g_MyPlayerConfig_instance_arr[v9_slot].f3A_flags =
//                (a2_data[a3_size - 5] >> 2) & 0x30   // 0011 0 000
//                | (a2_data[a3_size - 5] >> 1) & 0x8  // 0000 1 000
//                | (g_MyPlayerConfig_instance_arr[v9_slot].f3A_flags
//                  ^ (g_MyPlayerConfig_instance_arr[v9_slot].f3A_flags
//                    ^ a2_data[a3_size - 5]
//                  ) & 7
//                ) & 0xC7;                            // 1100 0 111
//        flags = arr[slot].flags & 7;
//        flags |= (arr[slot].flags & 0x08) << 1;  //  0000 1 000               00 0 1 0 000
//        flags |= (arr[slot].flags & 0x10) << 2;  //  0001 0 000  map present  01 0 0 0 000
//        flags |= (arr[slot].flags & 0xE0) << 2;  //  1110 0 000               10 0 0 0 000

        auto playerId = *(uint32_t *) pos;
        pos += sizeof(playerId);
        os << "playerId=" << fmtHex32(playerId) << " ";
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
        }
        return true;
    }

    void dk2Proto_printPlayersBuf(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        auto a3_playersSlotb = *pos++;
        auto humanPlayersCount = a3_playersSlotb & 0xF;
        auto aiPlayersCount = a3_playersSlotb >> 4;
        for (int i = 0; i < 8; ++i) {
            auto partSize = *(uint16_t *) pos;
            pos += sizeof(partSize);
            if(dk2Proto_hasPlayerBuf(pos, partSize)) {
                os << "  ";
                os << "slot=" << i << " ";
                dk2Proto_printPlayerBuf(os, pos, partSize);
                os << "\n";
            }
            pos += partSize;
        }
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "  ";
            os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
            os << "\n";
        }
    }
    uint8_t *dk2Proto_printLobbyStatusShort2(std::ostream &os, uint8_t *pos) {
        auto b1 = *pos++;
        auto b2 = *pos++;
        auto b3 = *pos++;
        auto b4 = *pos++;

        os << "flags=";
        if((b1 & 1) != 0) os << ",impenetrableWalls";
        if((b2 & 1) != 0) os << ",unk1";
        if((b3 & 1) != 0) os << ",fogOfWar";
        os << " ";

        os << "gameDuration=" << (int) (b1 >> 1) << " ";
        os << "maxCreatures=" << (int) (b2 >> 1) << " ";
        os << "manaRegeneration=" << (int) ((b3 >> 1) & 3) << " ";
        os << "gameSpeed=" << (int) ((b3 >> 3) & 3) << " ";
        os << "loseHeartType=" << (int) (b4 & 3) << " ";
        os << "goldDensity=" << (int) ((b4 >> 2) & 3) << " ";
        os << "maxPlayersCount=" << (int) (b4 >> 4) << " ";

        auto presentPlayerMask = *pos++;

        pos += dk2::CFrontEndComponent_instance.variable_creatures_count * 5;
        pos += dk2::CFrontEndComponent_instance.variable_p3_traps_sz * 5;
        pos += dk2::CFrontEndComponent_instance.variable_p4_rooms_sz * 5;
        pos += dk2::CFrontEndComponent_instance.variable_p5_spells_sz * 5;
        pos += dk2::CFrontEndComponent_instance.variable_p6_doors_sz * 5;

        return pos;
    }
    void dk2Proto_printLobbyStatusShort(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        pos = dk2Proto_printLobbyStatusShort2(os, pos);
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "CALC_SIZE_MISSMATCH=" << missmatch << " ";
            return;
        }
    }
    std::string AvailabilityValue_toString(size_t value) {
        switch (value) {
            case 0: return "None";
            case 1: return "Empty";
            case 2: return "Disable";
            case 3: return "Enable";
            case 4: return "EmptyRoom";
        }
        return "Unk" + std::to_string(value);
    }
    uint8_t *dk2Proto_printLobbyStatusLong2(std::ostream &os, uint8_t *pos) {
        pos += 4;
        auto kickedPlayerMask = *pos++;
        os << "  kickedPlayers=[";
        for (int i = 0; i < 8; ++i) {
            bool isKicked = ((1 << i) & kickedPlayerMask) != 0;
            if(!isKicked) continue;
            os << "," << i;
        }
        os << "]\n";

        os << "  creaturePoolValues=[";
        for (int i = 0; i < dk2::CFrontEndComponent_instance.variable_creatures_count; ++i) {
            if(i != 0) os << ",";
            auto id = *pos++;
            auto value = *(uint32_t *) pos;
            os << "(" << (int) id << "," << value << ")";
            pos += sizeof(value);
        }
        os << "]\n";
        os << "  availabilities:\n";
        os << "  traps=[";
        for (int i = 0; i < dk2::CFrontEndComponent_instance.variable_p3_traps_sz; ++i) {
            if(i != 0) os << ",";
            auto id = *pos++;
            auto value = *(uint32_t *) pos;
            os << "(" << (int) id << "," << AvailabilityValue_toString(value) << ")";
            pos += sizeof(value);
        }
        os << "]\n";
        os << "  rooms=[";
        for (int i = 0; i < dk2::CFrontEndComponent_instance.variable_p4_rooms_sz; ++i) {
            if(i != 0) os << ",";
            auto id = *pos++;
            auto value = *(uint32_t *) pos;
            os << "(" << (int) id << "," << AvailabilityValue_toString(value) << ")";
            pos += sizeof(value);
        }
        os << "]\n";
        os << "  spells=[";
        for (int i = 0; i < dk2::CFrontEndComponent_instance.variable_p5_spells_sz; ++i) {
            if(i != 0) os << ",";
            auto id = *pos++;
            auto value = *(uint32_t *) pos;
            os << "(" << (int) id << "," << AvailabilityValue_toString(value) << ")";
            pos += sizeof(value);
        }
        os << "]\n";
        os << "  doors=[";
        for (int i = 0; i < dk2::CFrontEndComponent_instance.variable_p6_doors_sz; ++i) {
            if(i != 0) os << ",";
            auto id = *pos++;
            auto value = *(uint32_t *) pos;
            os << "(" << (int) id << "," << AvailabilityValue_toString(value) << ")";
            pos += sizeof(value);
        }
        os << "]\n";
        return pos;
    }
    void dk2Proto_printLobbyStatusLong(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        pos = dk2Proto_printLobbyStatusLong2(os, pos);
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "  ";
            os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
            os << "\n";
        }
    }

    uint8_t *dumpMapName(std::ostream &os, uint8_t *pos) {
        for (int i = 0;; ++i) {
            auto ch = *(uint16_t *) pos;
            pos += sizeof(ch);
            if(ch == 0) break;
            if(0x20 <= ch && ch < 0x7F) {
                os << (char) ch;
            } else {
                os << "\\x" << fmtHex16(ch);
            }
            if((ch & 0xFF) == 0xFF) break;
        }
        return pos;
    }

    void dk2Proto_printGameStartInfoShort(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        os << "name=" << '"';
        pos = dumpMapName(os, pos);
        os << '"';
        os << ' ';
        pos = dk2Proto_printLobbyStatusShort2(os, pos);
        pos += 2 * 8;
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "  ";
            os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
            os << "\n";
        }
    }
    void dk2Proto_printGameStartInfoLong(std::ostream &os, void *data, size_t size) {
        uint8_t *pos = (uint8_t *) data;
        pos += 2 * (wcslen((const wchar_t *) pos) + 1);
        pos = dk2Proto_printLobbyStatusLong2(os, pos);
        for (int i = 0; i < 8; ++i) {
            os << "  player " << i << " ";
            pos = dk2Proto_printRelations(os, pos);
            os << '\n';
        }
        int missmatch = (pos - (uint8_t *) data) - size;
        if(missmatch != 0) {
            os << "  ";
            os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
            os << "\n";
        }
    }

    void actProto_print(std::ostream &os, dk2::GameAction &act) {

    }
    void dk2Proto_printShort(std::ostream &os, uint8_t ty, void *data, size_t size) {
        switch (ty) {
            case dk2::DK2Packet_1_ActionArr::ID: {
                auto *packet = (dk2::DK2Packet_1_ActionArr *) data;
                os << "tick0=" << packet->data.gameTick0 << " ";
                os << "tick5=" << packet->data.gameTick5 << " ";
                os << "f9=" << packet->data.dword_9 << " ";
                os << "fD=" << (int) packet->data.byte_d << " ";
                os << "fE=" << (int) packet->data.byte_e << " ";
                if(packet->data.actionArr_count == 0xFF) {
                    os << "count=FF ";
                } else {
                    os << "count=" << (int) packet->data.actionArr_count << " ";
                }

                int missmatch = packet->size() - size;
                if(missmatch != 0) {
                    os << "  ";
                    os << "BUF_SIZE_MISSMATCH=" << missmatch << " ";
                    os << "\n";
                }
            } break;
            case dk2::DK2Packet_2_GameAction::ID: {
                auto *packet = (dk2::DK2Packet_2_GameAction *) data;
                actProto_print(os, packet->act);
            } break;
//            case dk2::DK2Packet_B_UploadTrackPing::ID:
//            case dk2::DK2Packet_C_UploadTrackPong::ID:
            case dk2::DK2Packet_15_WorldChecksum::ID: {
                auto *packet = (dk2::DK2Packet_15_WorldChecksum *) data;
                os << "tick=" << packet->f0_gameTick << " ";
                os << "checksum=" << fmtHex32(packet->f4_checksum) << " ";
            } break;
            case dk2::DK2Packet_1F_LoadLevelStatus::ID: {
                auto *packet = (dk2::DK2Packet_1F_LoadLevelStatus *) data;
                os << "zero=" << packet->f0_zero << " ";
                os << "status=" << packet->f4_loadStatus << " ";
            } break;
            case dk2::DK2Packet_65_SyncTimingRequest::ID: {
                auto *packet = (dk2::DK2Packet_65_SyncTimingRequest *) data;
                os << "id=" << fmtHex32(packet->id) << " ";
            } break;
            case dk2::DK2Packet_66_UpdateTimings::ID: {
                auto *packet = (dk2::DK2Packet_66_UpdateTimings *) data;
                os << "id=" << fmtHex32(packet->id) << " ";
            } break;
//            case dk2::DK2Packet_67_AllTimings::ID:
            case 0x68: {  // PlayerBuf
//                dk2::MyPlayerConfig *cfgArr = &dk2::g_MyPlayerConfig_instance_arr[0];
//                if ((cfgArr[slot].flags & 7) == 1 ) {  // AI_PLAYER
//                    for (int i = 0; i < 8; ++i) {
//                        if ((cfgArr[i].flags & 7) != 0) continue;
//                        cfgArr[i] = cfgArr[slot];
//                        break;
//                    }
//                }
                dk2Proto_printPlayerBuf(os, data, size);
//                for (int i = 0; i < 8; ++i) {
//                    if ((cfgArr[i].flags & 7) != 1) continue;
//                    if (cfgArr[slot]._relations1[i] != 1) continue;
//                    cfgArr[i]._relations1[slot] = 1;
//                }
            } break;
            case 0x69: {  // SelectedMapName
                uint8_t *pos = (uint8_t *) data;
                os << "name=" << '"';
                pos = dumpMapName(os, pos);
                os << '"';
            } break;
            case 0x6B: {  // AllPlayersBuf
                uint8_t *pos = (uint8_t *) data;
                auto a3_playersSlotb = *pos++;
                auto humanPlayersCount = a3_playersSlotb & 0xF;
                auto aiPlayersCount = a3_playersSlotb >> 4;
                os << "humans=" << humanPlayersCount << " ";
                os << "computers=" << aiPlayersCount << " ";
            } break;
            case 0x6F: {  // CurrentLobbyStatus
                dk2Proto_printLobbyStatusShort(os, data, size);
            } break;
            case 0xC7: {  // GameStartInfo
                dk2Proto_printGameStartInfoShort(os, data, size);
            } break;
        }
    }

    void dk2Proto_printLong(std::ostream &os, uint8_t ty, void *data, size_t size, size_t slot) {
        switch (ty) {
//            case dk2::DK2Packet_1_ActionArr::ID:
//            case dk2::DK2Packet_B_UploadTrackPing::ID:
//            case dk2::DK2Packet_C_UploadTrackPong::ID:
//            case dk2::DK2Packet_15_WorldChecksum::ID:
//            case dk2::DK2Packet_1F_LoadLevelStatus::ID:
//            case dk2::DK2Packet_65_SyncTimingRequest::ID:
//            case dk2::DK2Packet_66_UpdateTimings::ID:
            case dk2::DK2Packet_67_AllTimings::ID: {
                auto *packet = (dk2::DK2Packet_67_AllTimings *) data;
                for (int i = 0; i < 8; ++i) {
                    os << "  totalTimeMs_shr4=" << packet->totalTimeMs_shr4[i] << " \n";
                }
            } break;
//            case 0x68:  // PlayerBuf
//            case 0x69:  // SelectedMapName
            case 0x6B: {  // AllPlayersBuf
                dk2Proto_printPlayersBuf(os, data, size);
            } break;
            case 0x6F: {  // CurrentLobbyStatus
                dk2Proto_printLobbyStatusLong(os, data, size);
            } break;
            case 0xC7: {  // GameStartInfo
                dk2Proto_printGameStartInfoLong(os, data, size);
            } break;
        }
    }

}

namespace {
    bool dk2Proto_dump = false;
    std::ofstream proto_os;
    DWORD dk2Proto_lastSave = 0;
}

void patch::protocol_dump::init() {
    if(!hasCmdOption("-dk2-proto-dump")) return;
    proto_os.open("dk2-proto.log");
    if(!proto_os.is_open()) {
        printf("[ERROR]: failed to open dk2 proto log\n");
        return;
    }
    proto_os << "Writing this to a file.\n";
    dk2Proto_dump = true;
}

void patch::protocol_dump::tick() {
    if(!dk2Proto_dump) return;
    DWORD now = GetTickCount();
    if((now - dk2Proto_lastSave) < 1000) return;
    dk2Proto_lastSave = now;
    proto_os.flush();
}

void patch::protocol_dump::onSend(size_t srcSlot, size_t dstSlot, void *data, size_t size, bool guaranteed) {
    if(!dk2Proto_dump) return;
    auto pkt = (dk2::DK2PacketHeader *) data;

    proto_os << dk2now() << ": send ";
    {
        std::stringstream ss;
        ss << dk2slot(srcSlot) << "->" << dk2slot(dstSlot);
        proto_os << std::setfill(' ') << std::setw(10) << std::left << ss.str() << std::right;
    }
    dk2Proto_printPacket(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1);
    if(guaranteed) proto_os << "gr=guar ";
    dk2Proto_printShort(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1);
    proto_os << "\n";
    dk2Proto_printLong(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1, dstSlot);
//    hexdump(proto_os, data, size);
}

void patch::protocol_dump::onRecv(size_t srcSlot, size_t dstSlot, void *data, size_t size, const char *group) {
    if(!dk2Proto_dump) return;
    if(srcSlot == dstSlot) return;
    auto pkt = (dk2::DK2PacketHeader *) data;

    proto_os << dk2now() << ": recv ";
    {
        std::stringstream ss;
        ss << dk2slot(dstSlot) << "<-" << dk2slot(srcSlot);
        proto_os << std::setfill(' ') << std::setw(10) << std::left << ss.str() << std::right;
    }
    dk2Proto_printPacket(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1);
    if(group) proto_os << "gr=" << group << " ";
    dk2Proto_printShort(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1);
    proto_os << "\n";
    dk2Proto_printLong(proto_os, pkt->packetId, (uint8_t *) data + 1, size - 1, srcSlot);
//    hexdump(proto_os, data, size);
}

void patch::protocol_dump::onRecvGuaranteed(size_t srcSlot, size_t dstSlot, void *data, size_t size) {
    if(!dk2Proto_dump) return;
    if(srcSlot == dstSlot) return;
    auto gdata = (dk2::MyGuaranteedData *) data;

    proto_os << dk2now() << ": recv ";
    {
        std::stringstream ss;
        ss << dk2slot(dstSlot) << "<-" << dk2slot(srcSlot);
        proto_os << std::setfill(' ') << std::setw(10) << std::left << ss.str() << std::right;
    }
    dk2Proto_printPacket(proto_os, gdata->gdTy, &gdata[1], size - sizeof(dk2::MyGuaranteedData));
    proto_os << "gr=guar ";
    dk2Proto_printShort(proto_os, gdata->gdTy, &gdata[1], size - sizeof(dk2::MyGuaranteedData));
    proto_os << "\n";
    dk2Proto_printLong(proto_os, gdata->gdTy, &gdata[1], size - sizeof(dk2::MyGuaranteedData), srcSlot);
}



