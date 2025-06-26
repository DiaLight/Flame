//
// Created by DiaLight on 6/10/2025.
//

#include "game_layout.h"

#include <vector>
#include <dk2/gui/WindowCfg.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <dk2/button/button_types.h>


namespace {

    dk2::WindowCfg Unk4_WinCfg {
            GWID_Unk4, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0,
            0, 0, 0, 0, 0, NULL, 0
    };

    dk2::WindowCfg Unk5_WinCfg {
            GWID_Unk5, 1, 0, 0, 1452, 980, 468, 0, 0, 980, 468, 0, NULL, NULL, 0,
            0, 0, 0, 0, 0, NULL, 0
    };

}

namespace {

    dk2::WindowCfg Game_endOfList_WinCfg {
        -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, NULL, 0
    };

    std::vector<dk2::WindowCfg *> windows;
}

dk2::WindowCfg **game_layout() {
    if (!windows.empty()) return windows.data();

    windows.emplace_back(ActivePanel_Rooms_layout());
    windows.emplace_back(ActivePanel_KeeperSpells_layout());
    windows.emplace_back(ActivePanel_WorkshopItems_layout());
    windows.emplace_back(&Unk4_WinCfg);
    windows.emplace_back(&Unk5_WinCfg);
    windows.emplace_back(ActivePanel_Creatures_layout());

    windows.emplace_back(Creatures_Total_layout());

    windows.emplace_back(Creatures_Jobs1_layout());
    windows.emplace_back(Creatures_Jobs2_layout());
    windows.emplace_back(Creatures_Jobs3_layout());
    windows.emplace_back(Creatures_Jobs4_layout());

    windows.emplace_back(Creatures_Combat1_layout());
    windows.emplace_back(Creatures_Combat2_layout());
    windows.emplace_back(Creatures_Combat3_layout());

    windows.emplace_back(Creatures_Moods1_layout());
    windows.emplace_back(Creatures_Moods2_layout());
    windows.emplace_back(Creatures_Moods3_layout());

    windows.emplace_back(ActivePanel_PanelTabs_layout());
    windows.emplace_back(ActivePanel_Minimap_layout());
    windows.emplace_back(TopPanel_InfoAndChat_layout());

    windows.emplace_back(Game_EscOptions_layout());
    windows.emplace_back(EscOptions_Load_layout());
    windows.emplace_back(EscOptions_Save_layout());
    windows.emplace_back(EscOptions_GameOptions_layout());
    windows.emplace_back(GameOptions_GraphicsOptions_layout());
    windows.emplace_back(GameOptions_SoundOptions_layout());
    windows.emplace_back(GameOptions_AdvancedSoundOptions_layout());
    windows.emplace_back(GameOptions_ControlOptions_layout());
    windows.emplace_back(ControlOptions_DefineKeys_layout());
    windows.emplace_back(GameOptions_DefineUserCameras_layout());
    windows.emplace_back(DefineUserCameras_AdjustCamera_layout());
    windows.emplace_back(EscOptions_LevelObjective_layout());
    windows.emplace_back(EscOptions_EndGame_layout());
    windows.emplace_back(EndGame_Confirm_layout());

    windows.emplace_back(Misc_GeneralError_layout());
    windows.emplace_back(Misc_ErrorFirstFight_layout());

    windows.emplace_back(Misc_PlayerInformation_layout());

    windows.emplace_back(ActivePanel_ObjectiveAndNotifications_layout());
    windows.emplace_back(ActivePanel_NotificationMessage_layout());
    windows.emplace_back(ActivePanel_SummonHorny_layout());
    windows.emplace_back(Misc_MultiplayerAlly_layout());
    windows.emplace_back(ActivePanel_Alarms_layout());

    windows.emplace_back(ActivePanel_HeroPortalControl_layout());
    windows.emplace_back(Counters_TimeRemaining_layout());
    windows.emplace_back(Counters_MpdScore_layout());
    windows.emplace_back(Counters_CurrentCrownHolder_layout());

    windows.emplace_back(Counters_MpdHeroesKilled_layout());
    windows.emplace_back(Counters_MpdSlapsRemaining_layout());
    windows.emplace_back(Counters_MpdNextRoom_layout());
    windows.emplace_back(Misc_ContinueGame_layout());
    windows.emplace_back(Misc_DropDownList_layout());
    windows.emplace_back(TopPanel_ActiveDescription_layout());

    windows.emplace_back(&Game_endOfList_WinCfg);

    return windows.data();
}
