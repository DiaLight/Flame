//
// Created by DiaLight on 05.01.2025.
//

#ifndef FLAME_MESSAGES_H
#define FLAME_MESSAGES_H

#include <Windows.h>
#include "structs.h"

namespace net {

#pragma pack(push, 1)
struct MyMessage_1_AddedPlayer {
    BYTE f0_message;
    int f1_flags;  // 4: SPECTATOR
    BYTE f5_slotNo;
    wchar_t f6_playerName[16];
    PlayerId f26_playerId_slot;
};
#pragma pack(pop)
static_assert(sizeof(MyMessage_1_AddedPlayer) == 0x2A);

}  // namespace net

#endif //FLAME_MESSAGES_H
