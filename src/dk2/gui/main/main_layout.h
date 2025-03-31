//
// Created by DiaLight on 4/3/2025.
//

#ifndef MAIN_LAYOUT_H
#define MAIN_LAYOUT_H


#define EngOfButtonList {\
    0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,\
    0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0\
}

enum WindowId {
    WID_Main = 1,
    WID_SinglePlayer = 2,
    WID_Multiplayer = 3,
    WID_Options = 4,
    WID_ViewMovies = 5,
    WID_Extras = 6,
    WID_MissionBriefing = 7,
    WID_LoadGame = 8,
    WID_Scirmish = 9,
    WID_IpxLocalNetwork = 10,
    WID_TcpIpInternet = 11,
    WID_Graphics = 15,
    WID_Sound = 16,
    WID_Control = 17,
    WID_TodaysTopKeepers = 18,
    WID_MissionDebriefing_StatsShort = 26,
    WID_MissionDebriefing_StatsLong1 = 27,
    WID_AddressBook = 30,
    WID_CreateLobby = 32,
    WID_Multiplayer_MapSelect = 33,
    WID_Skirmish_MapSelect = 34,
    WID_GameSettings = 35,
    WID_Map3d = 37,
    WID_MyPetDungeon = 38,
    WID_InternetDungeonWatch = 39,
    WID_Credits = 40,
    WID_MissionDebriefing_StatsMiddle = 42,
    WID_Quit = 44,
    WID_MissionDebriefing_StatsLong2 = 45,
    WID_PlayerList = 46,
    WID_UnkList = 47,
    WID_MyPetDungeon_Other = 48,
};

dk2::WindowCfg **main_layout();


#endif //MAIN_LAYOUT_H
