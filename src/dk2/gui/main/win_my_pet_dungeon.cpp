//
// Created by DiaLight on 4/3/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "main_layout.h"

namespace {

    dk2::ButtonCfg Main_MyPetDungeon_BtnArr[] {
        {
            BT_CTextBox, 560, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 44, 2560, 140, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 21, 0x00000000, 0x00000000, 0
        },
        {
            BT_CClickButton, 539, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            612, 260, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000000, 0x000D0002, 33
        },
        {
            BT_CClickButton, 540, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000001, 0,
            612, 468, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000001, 0x000D0002, 33
        },
        {
            BT_CClickButton, 541, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000002, 0,
            612, 676, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000002, 0x000D0002, 33
        },
        {
            BT_CClickButton, 542, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000003, 0,
            612, 884, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000003, 0x000D0002, 33
        },
        {
            BT_CClickButton, 543, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000004, 0,
            612, 1092, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000004, 0x000D0002, 33
        },
        {
            BT_CClickButton, 544, 0, dk2::CButton_handleLeftClick_542070, NULL, 0, 0, 0x00000000, 0x00000005, 0,
            612, 1300, 1340, 188, 0, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000005, 0x000D0002, 33
        },
        {
            BT_CClickButton, 561, 0, dk2::CButton_handleLeftClick_542070, NULL, 48, 1, 0x00000005, 0x00000006, 0,
            612, 1544, 1340, 188, 1, 0, 1340, 188, 0, NULL, dk2::CButton_render_541F50, 0x00000000, 0, 0x00000006, 0x000D0002, 33
        },
        {
            BT_CClickButton, 538, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 1, 0x00000000, 0x0000005D, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000001, 0x00000000, 36
        },

        EngOfButtonList,
    };

    dk2::WindowCfg Main_MyPetDungeon_WinCfg {
        WID_MyPetDungeon, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, NULL, 0,
        0, 0, 0, 0, 0, Main_MyPetDungeon_BtnArr, 4
    };
}

dk2::WindowCfg *Main_MyPetDungeon_layout() {
    return &Main_MyPetDungeon_WinCfg;
}

