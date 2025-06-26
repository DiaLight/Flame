//
// Created by DiaLight on 6/10/2025.
//

#ifndef GAME_LAYOUT_H
#define GAME_LAYOUT_H

#define EngOfButtonList {\
    0, 0xFFFFFFFF, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,\
    0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, NULL, 0, 0x00000000, 0x00000000, 0\
}

enum GameWindowId {
    GWID_ActivePanel_Rooms = 1,
    GWID_ActivePanel_KeeperSpells = 2,
    GWID_ActivePanel_WorkshopItems = 3,
    GWID_Unk4 = 4,
    GWID_Unk5 = 5,
    GWID_ActivePanel_Creatures = 6,
    GWID_Creatures_Total = 7,
    GWID_Creatures_Jobs1 = 8,
    GWID_Creatures_Jobs2 = 9,
    GWID_Creatures_Jobs3 = 10,
    GWID_Creatures_Jobs4 = 11,
    GWID_Creatures_Combat1 = 12,
    GWID_Creatures_Combat2 = 13,
    GWID_Creatures_Combat3 = 14,
    GWID_Creatures_Moods1 = 15,
    GWID_Creatures_Moods2 = 16,
    GWID_Creatures_Moods3 = 17,
    GWID_ActivePanel_PanelTabs = 18,
    GWID_Unused19 = 19,
    GWID_ActivePanel_MiniMap = 20,
    GWID_TopPanel_InfoAndChat = 21,
    GWID_EscOptions = 22,
    GWID_EscOptions_Load = 23,
    GWID_EscOptions_Save = 24,
    GWID_EscOptions_GameOptions = 25,
    GWID_GameOptions_GraphicsOptions = 26,
    GWID_GameOptions_SoundOptions = 27,
    GWID_SoundOptions_AdvancedSoundOptions = 28,
    GWID_GameOptions_ControlOptions = 29,
    GWID_ControlOptions_DefineKeys = 30,
    GWID_DefineUserCameras = 31,
    GWID_DefineUserCameras_AdjustCamera = 32,
    GWID_EscOptions_LevelObjective = 33,
    GWID_EscOptions_ExitGame = 34,
    GWID_ExitGame_Confirm = 35,
    GWID_Misc_GeneralError = 36,
    GWID_Misc_ErrorFirstFight = 37,
    GWID_Misc_PlayerInformation = 38,
    GWID_ActivePanel_ObjectiveAndNotifications = 39,
    GWID_ActivePanel_NotificationMessage = 40,
    GWID_ActivePanel_SummonHorny = 41,
    GWID_Multiplayer_Ally = 42,
    GWID_ActivePanel_Alarms = 43,
    GWID_ActivePanel_HeroPortalControl = 44,
    GWID_Counters_TimeRemaining = 45,
    GWID_Counters_MpdScore = 46,
    GWID_Counters_CurrentCrownHolder = 47,
    GWID_Counters_MpdHeroesKilled = 48,
    GWID_Counters_MpdSlapsRemaining = 49,
    GWID_Counters_MpdNextRoom = 50,
    GWID_Misc_ContinueGame = 51,
    GWID_Misc_DropDownList = 52,
    GWID_TopPanel_ActiveDescription = 53,
};

namespace dk2 {
    struct WindowCfg;
}


dk2::WindowCfg *ActivePanel_Rooms_layout();
dk2::WindowCfg *ActivePanel_KeeperSpells_layout();
dk2::WindowCfg *ActivePanel_WorkshopItems_layout();
dk2::WindowCfg *ActivePanel_Creatures_layout();

dk2::WindowCfg *Creatures_Total_layout();

dk2::WindowCfg *Creatures_Jobs1_layout();
dk2::WindowCfg *Creatures_Jobs2_layout();
dk2::WindowCfg *Creatures_Jobs3_layout();
dk2::WindowCfg *Creatures_Jobs4_layout();

dk2::WindowCfg *Creatures_Combat1_layout();
dk2::WindowCfg *Creatures_Combat2_layout();
dk2::WindowCfg *Creatures_Combat3_layout();

dk2::WindowCfg *Creatures_Moods1_layout();
dk2::WindowCfg *Creatures_Moods2_layout();
dk2::WindowCfg *Creatures_Moods3_layout();

dk2::WindowCfg *ActivePanel_PanelTabs_layout();
dk2::WindowCfg *ActivePanel_Minimap_layout();
dk2::WindowCfg *TopPanel_InfoAndChat_layout();

dk2::WindowCfg *Game_EscOptions_layout();
dk2::WindowCfg *EscOptions_Load_layout();
dk2::WindowCfg *EscOptions_Save_layout();
dk2::WindowCfg *EscOptions_GameOptions_layout();

dk2::WindowCfg *GameOptions_GraphicsOptions_layout();
dk2::WindowCfg *GameOptions_SoundOptions_layout();
dk2::WindowCfg *GameOptions_AdvancedSoundOptions_layout();
dk2::WindowCfg *GameOptions_ControlOptions_layout();
dk2::WindowCfg *ControlOptions_DefineKeys_layout();
dk2::WindowCfg *GameOptions_DefineUserCameras_layout();
dk2::WindowCfg *DefineUserCameras_AdjustCamera_layout();

dk2::WindowCfg *EscOptions_LevelObjective_layout();
dk2::WindowCfg *EscOptions_EndGame_layout();
dk2::WindowCfg *EndGame_Confirm_layout();

dk2::WindowCfg *Misc_GeneralError_layout();
dk2::WindowCfg *Misc_ErrorFirstFight_layout();
dk2::WindowCfg *Misc_PlayerInformation_layout();

dk2::WindowCfg *ActivePanel_ObjectiveAndNotifications_layout();
dk2::WindowCfg *ActivePanel_NotificationMessage_layout();
dk2::WindowCfg *ActivePanel_SummonHorny_layout();

dk2::WindowCfg *Misc_MultiplayerAlly_layout();

dk2::WindowCfg *ActivePanel_Alarms_layout();
dk2::WindowCfg *ActivePanel_HeroPortalControl_layout();

dk2::WindowCfg *Counters_TimeRemaining_layout();
dk2::WindowCfg *Counters_MpdScore_layout();
dk2::WindowCfg *Counters_CurrentCrownHolder_layout();
dk2::WindowCfg *Counters_MpdHeroesKilled_layout();
dk2::WindowCfg *Counters_MpdSlapsRemaining_layout();
dk2::WindowCfg *Counters_MpdNextRoom_layout();
dk2::WindowCfg *Misc_ContinueGame_layout();
dk2::WindowCfg *Misc_DropDownList_layout();

dk2::WindowCfg *TopPanel_ActiveDescription_layout();


dk2::WindowCfg **game_layout();


#endif //GAME_LAYOUT_H
