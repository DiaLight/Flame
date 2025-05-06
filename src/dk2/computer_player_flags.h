//
// Created by DiaLight on 02.05.2025.
//

#ifndef FLAME_COMPUTER_PLAYER_FLAGS_H
#define FLAME_COMPUTER_PLAYER_FLAGS_H


#include <cstdint>

namespace dk2 {
    struct MyComputerPlayer;
}

enum MyComputerPlayer_flags {
    MCPF_Opened             = 0x00000001,
    MCPF_WallHug            = 0x00000002,
    MCPF_WallHugLeft        = 0x00000004,
    MCPF_FightGoingOn       = 0x00000008,
    MCPF_NextRoomToBuildSet = 0x00000010,
    MCPF_AllRoomsBuilt      = 0x00000020,
    MCPF_HaveBeenAttacked   = 0x00000040,
    MCPF_CallToArmsInUse    = 0x00000080,
    MCPF_gtDirection        = 0x00000300,  // (f0_flags >> 8) & 3
    MCPF_DefendDirection    = 0x00000C00,  // (f0_flags >> 10) & 3
    MCPF_OpenDirection      = 0x00003000,  // (f0_flags >> 12) & 3
    MCPF_CurrentEventTask   = 0x0003C000,  // (f0_flags >> 14) & 0xF
    MCPF_NumberOfEventTasks = 0x003C0000,  // (f0_flags >> 18) & 0xF
    MCPF_Task               = 0x03C00000,  // (f0_flags >> 22) & 0xF
    MCPF_NextTask           = 0x3C000000,  // (f0_flags >> 26) & 0xF
    MCPF_TrapsStartFights   = 0x40000000,
    MCPF_TimesOut           = 0x80000000,
};

int currentEventTask_fromFlags(uint32_t flags);
uint32_t currentEventTask_toFlags(int value);
int getCurrentEventTask(dk2::MyComputerPlayer *cp);

int numberOfEventTasks_fromFlags(uint32_t flags);
uint32_t numberOfEventTasks_toFlags(int value);
int getNumberOfEventTasks(dk2::MyComputerPlayer *cp);

int task_fromFlags(uint32_t flags);
uint32_t task_toFlags(int value);
int getTask(dk2::MyComputerPlayer *cp);

int nextTask_fromFlags(uint32_t flags);
uint32_t nextTask_toFlags(int value);
int getNextTask(dk2::MyComputerPlayer *cp);


enum MyComputerPlayer_buildFlags {
    MCPBF_CreateEmptyRoomShapeAreasWhenIdle               = 0x00000001,
    MCPBF_AutomaticallyBuildBiggerLairWhenPortalTakenOver = 0x00000002,
    MCPBF_TilesLeftBetweenRooms                           = 0x0000003C,  // (this->buildFlags >> 2) & 0xF);
    MCPBF_PlaceRoomsNextToIdeal                           = 0x00000040,
    MCPBF_BuildNewRoomWhenMoreSpaceRequired               = 0x00000180,  // (this->buildFlags >> 7) & 3);
    MCPBF_AggressiveVsDefensiveTrapPreference             = 0x00000E00,  // (this->buildFlags >> 9) & 7);
    MCPBF_TrapVsDoorPreference                            = 0x00007000,  // (this->buildFlags >> 12) & 7);
    MCPBF_DoorPreference                                  = 0x00018000,  // (this->buildFlags >> 15) & 3);
    MCPBF_ProbabilityOfMovingCreatureForResearch          = 0x00060000,  // (this->buildFlags >> 17) & 3);
    MCPBF_IACreatureSkillLevel                            = 0x00780000,  // (this->buildFlags >> 19) & 0xF);
    MCPBF_IAAllRoomsPlaced                                = 0x00800000,
    MCPBF_IAAllSpellsResearched                           = 0x01000000,
    MCPBF_IAOnlyAttackAttackers                           = 0x02000000,
    MCPBF_AttackingVsDefensiveSpellPreference             = 0x1C000000,  // (this->buildFlags >> 26) & 7);
    MCPBF_BoulderTrapsOnLongCorridors                     = 0x20000000,
    MCPBF_BARemoveIfCantReinforce                         = 0x40000000,
};

int probabilityOfMovingCreatureForResearch_fromFlags(uint32_t flags);
uint32_t probabilityOfMovingCreatureForResearch_toFlags(int value);
int getProbabilityOfMovingCreatureForResearch(dk2::MyComputerPlayer *cp);

enum MyComputerPlayer_flags2 {
    MCPF2_UseKeeperSpells           = 0x00000007,  // (this->flags2 >> 0) & 7);
    MCPF2_IAFirstStart              = 0x00000018,  // (this->flags2 >> 3) & 3);
    MCPF2_IAFirstEnd                = 0x00000060,  // (this->flags2 >> 5) & 3);
    MCPF2_SellRecentlyTakenOverRoom = 0x00000080,
    MCPF2_CorridorStyle             = 0x00000300,  // (this->flags2 >> 8) & 3);
    MCPF2_BoulderTrapOnBreachRoute  = 0x00000400,
    MCPF2_BreachAtXPoints           = 0x00007800,  // (this->flags2 >> 11) & 0xF);
    MCPF2_UnhappyCreaturesHappy     = 0x00008000,
    MCPF2_AngryCreaturesHappy       = 0x00010000,
    MCPF2_AngryCreaturesDisposeOf   = 0x00020000,
    MCPF2_AngryDisposalMethod       = 0x00040000,
    MCPF2_UnwantedCreatureDisposeOf = 0x00080000,
    MCPF2_UseSightOfEvil            = 0x00300000,  // (this->flags2 >> 20) & 3);
    MCPF2_LightningInWater          = 0x00400000,
    MCPF2_SpellPreference           = 0x03800000,  // (this->flags2 >> 23) & 7);
    MCPF2_CallToArmsUsage           = 0x0C000000,  // (this->flags2 >> 26) & 3);
    MCPF2_ImprisonedCreatureAction  = 0x30000000,  // (this->flags2 >> 28) & 3);
    MCPF2_NeverAttack               = 0x40000000,
};





#endif //FLAME_COMPUTER_PLAYER_FLAGS_H
