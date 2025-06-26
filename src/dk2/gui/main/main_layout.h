//
// Created by DiaLight on 4/3/2025.
//

#ifndef MAIN_LAYOUT_H
#define MAIN_LAYOUT_H


#define EngOfButtonList {\
    0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,\
    0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0\
}

enum MainWindowId {
    MWID_Main = 1,
    MWID_SinglePlayer = 2,
    MWID_Multiplayer = 3,
    MWID_Options = 4,
    MWID_ViewMovies = 5,
    MWID_Extras = 6,
    MWID_MissionBriefing = 7,
    MWID_LoadGame = 8,
    MWID_Scirmish = 9,
    MWID_IpxLocalNetwork = 10,
    MWID_TcpIpInternet = 11,
    MWID_Graphics = 15,
    MWID_Sound = 16,
    MWID_Control = 17,
    MWID_TodaysTopKeepers = 18,
    MWID_MissionDebriefing_StatsShort = 26,
    MWID_MissionDebriefing_StatsLong1 = 27,
    MWID_AddressBook = 30,
    MWID_CreateLobby = 32,
    MWID_Multiplayer_MapSelect = 33,
    MWID_Skirmish_MapSelect = 34,
    MWID_GameSettings = 35,
    MWID_Map3d = 37,
    MWID_MyPetDungeon = 38,
    MWID_InternetDungeonWatch = 39,
    MWID_Credits = 40,
    MWID_MissionDebriefing_StatsMiddle = 42,
    MWID_Quit = 44,
    MWID_MissionDebriefing_StatsLong2 = 45,
    MWID_PlayerList = 46,
    MWID_UnkList = 47,
    MWID_MyPetDungeon_Other = 48,

    // flame patch
    MWID_SinglePlayer_CustomCampaign = 50,
};

dk2::WindowCfg **main_layout();


#endif //MAIN_LAYOUT_H
