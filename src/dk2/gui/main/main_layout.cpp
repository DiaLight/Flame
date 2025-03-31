//
// Created by DiaLight on 4/3/2025.
//

#include <dk2/gui/WindowCfg.h>
#include "main_layout.h"

#include <dk2_functions.h>
#include <dk2_globals.h>
#include <vector>
#include <dk2/button/button_types.h>


namespace {


    void __cdecl CListBox__ret(dk2::CVerticalSlider *, dk2::CFrontEndComponent *) {}

    dk2::ButtonCfg UnkList_BtnArr[] {
        {
            BT_CListBox, 1, 0, NULL, NULL, 0, 0, (uint32_t) dk2::CListBox__547EA0, (uint32_t) dk2::CListBox__547EB0, 0,
            0, 0, 400, 680, 0, 0, 400, 680, 0, dk2::CListBox_sub_530440, CListBox__ret, (uint32_t) dk2::CVerticalSlider_550420, 0, 0x00000000, 0x00000000, 0
        },

        EngOfButtonList,
    };

    dk2::WindowCfg UnkList_WinCfg {
        WID_UnkList, 0, 0, 0, 1000, 400, 680, 0, 0, 400, 680, 0, NULL, NULL, 8,
        0, 0, 0, 0, 0, UnkList_BtnArr, 0
    };


    dk2::WindowCfg Main_endOfList_WinCfg {
        -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, NULL, 0
    };

    std::vector<dk2::WindowCfg *> windows;
}

dk2::WindowCfg *Main_Main_layout();
dk2::WindowCfg *Main_SinglePlayer_layout();
dk2::WindowCfg *Main_Multiplayer_layout();
dk2::WindowCfg *Main_Options_layout();
dk2::WindowCfg *Extras_ViewMovies_layout();
dk2::WindowCfg *Main_Extras_layout();
dk2::WindowCfg *Map3d_MissionBriefing_layout();
dk2::WindowCfg *Main_LoadGame_layout();
dk2::WindowCfg *Main_Scirmish_layout();
dk2::WindowCfg *Multiplayer_IpxLocalNetwork_layout();
dk2::WindowCfg *Multiplayer_TcpIpInternet_layout();
dk2::WindowCfg *Options_Graphics_layout();
dk2::WindowCfg *Options_Sound_layout();
dk2::WindowCfg *Options_Control_layout();
dk2::WindowCfg *Extras_TodaysTopKeepers_layout();
dk2::WindowCfg *MissionDebriefing_StatsShort_layout();
dk2::WindowCfg *Net_AddressBook_layout();
dk2::WindowCfg *Net_CreateLobby_layout();
dk2::WindowCfg *Skirmish_MapSelect_layout();
dk2::WindowCfg *Multiplayer_MapSelect_layout();
dk2::WindowCfg *GameSettings_layout();
dk2::WindowCfg *Map3d_layout();
dk2::WindowCfg *Main_MyPetDungeon_layout();
dk2::WindowCfg *Net_InternetDungeonWatch_layout();
dk2::WindowCfg *Extras_Credits_layout();
dk2::WindowCfg *MissionDebriefing_StatsMiddle_layout();
dk2::WindowCfg *MissionDebriefing_StatsLong1_layout();
dk2::WindowCfg *MissionDebriefing_StatsLong2_layout();
dk2::WindowCfg *Main_Quit_layout();
// dk2::WindowCfg *UnkList_layout();
dk2::WindowCfg *CreateLobby_PlayerList_layout();
dk2::WindowCfg *MyPetDungeon_Other_layout();



dk2::WindowCfg **main_layout() {
    if (!windows.empty()) return windows.data();

    windows.emplace_back(Main_Main_layout());  // 1
    windows.emplace_back(Main_SinglePlayer_layout()); // 2
    windows.emplace_back(Main_Multiplayer_layout()); // 3
    windows.emplace_back(Main_Options_layout()); // 4
    windows.emplace_back(Extras_ViewMovies_layout()); // 5
    windows.emplace_back(Main_Extras_layout()); // 6
    windows.emplace_back(Map3d_MissionBriefing_layout()); // 7
    windows.emplace_back(Main_LoadGame_layout()); // 8
    windows.emplace_back(Main_Scirmish_layout()); // 9
    windows.emplace_back(Multiplayer_IpxLocalNetwork_layout()); // 10
    windows.emplace_back(Multiplayer_TcpIpInternet_layout()); // 11
    windows.emplace_back(Options_Graphics_layout()); // 15
    windows.emplace_back(Options_Sound_layout()); // 16
    windows.emplace_back(Options_Control_layout()); // 17
    windows.emplace_back(Extras_TodaysTopKeepers_layout()); // 18
    windows.emplace_back(MissionDebriefing_StatsShort_layout()); // 26
    windows.emplace_back(Net_AddressBook_layout()); // 30
    windows.emplace_back(Net_CreateLobby_layout()); // 32
    windows.emplace_back(Skirmish_MapSelect_layout()); // 34
    windows.emplace_back(Multiplayer_MapSelect_layout()); // 33
    windows.emplace_back(GameSettings_layout()); // 35
    windows.emplace_back(Map3d_layout()); // 37
    windows.emplace_back(Main_MyPetDungeon_layout()); // 38
    windows.emplace_back(Net_InternetDungeonWatch_layout()); // 39
    windows.emplace_back(Extras_Credits_layout()); // 40
    windows.emplace_back(MissionDebriefing_StatsMiddle_layout()); // 42
    windows.emplace_back(MissionDebriefing_StatsLong1_layout()); // 27
    windows.emplace_back(MissionDebriefing_StatsLong2_layout()); // 45
    windows.emplace_back(Main_Quit_layout()); // 44
    windows.emplace_back(&UnkList_WinCfg); // 47
    windows.emplace_back(CreateLobby_PlayerList_layout()); // 46
    windows.emplace_back(MyPetDungeon_Other_layout()); // 48

    windows.emplace_back(&Main_endOfList_WinCfg);

    return windows.data();
}
