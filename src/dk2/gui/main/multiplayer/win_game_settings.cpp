//
// Created by DiaLight on 4/3/2025.
//

#include <dk2_functions.h>
#include <memory>
#include <vector>
#include <dk2/button/button_types.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/WindowCfg.h>
#include "../main_layout.h"

namespace {

    dk2::ButtonCfg GameSettings_BtnArr[] {
        {
            BT_CTextBox, 663, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 272, 228, 88, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54ABB0, 0x00000000, 1, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 664, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            64, 472, 172, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54ABB0, 0x00000000, 2, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 665, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2172, 436, 212, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54ABB0, 0x00000000, 3, 0x00000000, 0x00000000, 0
        },
        {
            BT_CVerticalSlider, 662, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1400, 464, 48, 680, 0, 0, 48, 680, 0, dk2::CButton_f34_549620, dk2::CVerticalSlider_render_551490, 0x00000000, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CClickButton, 593, 0, dk2::CButton_handleLeftClick_54A4D0, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 264, 380, 136, 0, 0, 340, 136, 0, NULL, dk2::CButton_render_532310, 0x00000000, 305, 0x00000000, 0x00020000, 33
        },
        {
            BT_CClickButton, 594, 0, dk2::CButton_handleLeftClick_54A4D0, NULL, 0, 0, 0x00000002, 0x00000000, 0,
            340, 264, 340, 136, 0, 0, 340, 136, 0, NULL, dk2::CButton_render_532310, 0x00000000, 315, 0x00000000, 0x00020000, 33
        },
        {
            BT_CClickButton, 595, 0, dk2::CButton_handleLeftClick_54A4D0, NULL, 0, 0, 0x00000003, 0x00000000, 0,
            600, 264, 500, 136, 0, 0, 340, 136, 0, NULL, dk2::CButton_render_532310, 0x00000000, 320, 0x00000000, 0x00020000, 33
        },
        {
            BT_CClickButton, 596, 0, dk2::CButton_handleLeftClick_54A4D0, NULL, 0, 0, 0x00000001, 0x00000000, 0,
            1020, 264, 340, 136, 0, 0, 340, 136, 0, NULL, dk2::CButton_render_532310, 0x00000000, 324, 0x00000000, 0x00020000, 33
        },
        {
            BT_CClickButton, 597, 0, dk2::CButton_handleLeftClick_54A4D0, NULL, 0, 0, 0x00000004, 0x00000000, 0,
            1360, 264, 340, 136, 0, 0, 340, 136, 0, NULL, dk2::CButton_render_532310, 0x00000000, 330, 0x00000000, 0x00020000, 33
        },
        {
            BT_CTextBox, 598, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            68, 464, 436, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 83, 0x00000000, 0x00010001, 0
        },
        {
            BT_CTextBox, 599, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            824, 464, 408, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 293, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 600, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 464, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54AA50, 0x00000000, 0, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 601, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1080, 464, 312, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 321, 0x00000000, 0x00010000, 0
        },
        {
            BT_CTextBox, 604, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            68, 1432, 1152, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 348, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 602, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1268, 1432, 120, 120, 0, 0, 120, 120, 0, dk2::CButton_f34_54AF70, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CTextBox, 605, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            68, 1636, 1152, 120, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 2906, 0x00000000, 0x00030001, 0
        },
        {
            BT_CCheckBoxButton, 603, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1268, 1632, 120, 116, 0, 0, 120, 116, 0, dk2::CButton_f34_54AFA0, dk2::CButton_render_536190, 0x00000000, 0, 0x00000000, 0x00000000, 34
        },
        {
            BT_CHorizontalSlider, 606, 0, NULL, NULL, 0, 0, 0x00000001, 0x00000010, 0,
            1680, 968, 684, 48, 0, 0, 684, 48, 0, dk2::CButton_f34_54AD40, dk2::CButton_render_550D90, 0x00000000, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 607, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            1680, 1164, 684, 48, 0, 0, 684, 48, 0, dk2::CButton_f34_54ADD0, dk2::CButton_render_550D90, 0x00000000, 1, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 608, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000002, 0,
            1680, 1364, 684, 48, 0, 0, 684, 48, 0, dk2::Button_updateGoldDensity, dk2::CButton_render_550D90, 0x00000000, 2, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 609, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000002, 0,
            1680, 1564, 684, 48, 0, 0, 684, 48, 0, dk2::Button_updateManaRegeneration, dk2::CButton_render_550D90, 0x00000000, 3, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 610, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1576, 456, 640, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 1533, 0x00000000, 0x00030001, 0
        },
        {
            BT_CTextBox, 612, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1576, 848, 636, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 1469, 0x00000000, 0x00030001, 0
        },
        {
            BT_CTextBox, 613, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1576, 1060, 636, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 1530, 0x00000000, 0x00030001, 0
        },
        {
            BT_CTextBox, 614, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1576, 1256, 636, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 1535, 0x00000000, 0x00030001, 0
        },
        {
            BT_CTextBox, 615, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1576, 1460, 636, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 1531, 0x00000000, 0x00030001, 0
        },
        {
            BT_CTextInput, 616, 0, dk2::Button_updateGameDuration, NULL, 0, 0, 0x00000000, 0x00000004, 0,
            2300, 456, 240, 92, 0, 0, 240, 92, 0, NULL, dk2::CTextInput_render_52FF10, 0x00000000, 3, 0x00000000, 0x00000001, 32
        },
        {
            BT_CTextBox, 620, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2220, 848, 336, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000003, 0x00000002, 0
        },
        {
            BT_CTextBox, 624, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2224, 1060, 328, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000003, 0x00000002, 0
        },
        {
            BT_CTextBox, 625, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2224, 1256, 328, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 626, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            2224, 1460, 328, 92, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 627, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            0, 8, 2560, 224, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_536700, 0x00000000, 3, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 636, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 1164, 1316, 104, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_532310, 0x00000000, 341, 0x00000000, 0x00030001, 0
        },
        {
            BT_CClickButton, 637, 0, dk2::CButton_handleLeftClick_54AC90, dk2::CButton_handleLeftClick_54AC90, 0, 0, 0x00000000, 0x00000005, 0,
            72, 1272, 1316, 104, 0, 0, 1316, 104, 0, NULL, dk2::CButton_render_532670, 0x00000000, 1537, 0x00000005, 0x000E0001, 33
        },
        {
            BT_CTextBox, 628, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 540, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 0, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 629, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 616, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 1, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 630, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 692, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 2, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 631, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 768, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 3, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 632, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 844, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 4, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 633, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 920, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 5, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 634, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 988, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 6, 0x00000000, 0x00000000, 0
        },
        {
            BT_CTextBox, 635, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            72, 1064, 848, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A8A0, 0x00000000, 7, 0x00000000, 0x00000000, 0
        },
        {
            BT_CHorizontalSlider, 638, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 564, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_5496B0, dk2::CVerticalSlider_550A10, 0x00000000, 0, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 639, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 640, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549770, dk2::CVerticalSlider_550A10, 0x00000000, 1, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 640, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 716, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549830, dk2::CVerticalSlider_550A10, 0x00000000, 2, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 641, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 792, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549900, dk2::CVerticalSlider_550A10, 0x00000000, 3, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 642, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 868, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_5499D0, dk2::CVerticalSlider_550A10, 0x00000000, 4, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 643, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 944, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549AA0, dk2::CVerticalSlider_550A10, 0x00000000, 5, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 644, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 1020, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549B70, dk2::CVerticalSlider_550A10, 0x00000000, 6, 0x00000000, 0x00000040, 27
        },
        {
            BT_CHorizontalSlider, 645, 0, NULL, NULL, 0, 0, 0x00000000, 0x00000020, 0,
            824, 1096, 412, 48, 0, 0, 412, 48, 0, dk2::CButton_f34_549C40, dk2::CVerticalSlider_550A10, 0x00000000, 7, 0x00000000, 0x00000040, 27
        },
        {
            BT_CTextBox, 646, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 540, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 647, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 616, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 648, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 692, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 649, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 768, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 650, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 844, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 651, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 920, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 652, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 996, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CTextBox, 653, 255, NULL, NULL, 0, 0, 0x00000000, 0x00000000, 0,
            1228, 1072, 156, 80, 0, 0, 0, 0, 0, NULL, dk2::CButton_render_54A710, 0x00000000, 0, 0x00000002, 0x00000002, 0
        },
        {
            BT_CClickButton, 654, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x0000028E, 0x00000000, 0,
            1080, 540, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 655, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x0000028F, 0x00000001, 0,
            1080, 616, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 656, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000290, 0x00000002, 0,
            1080, 692, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 657, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000291, 0x00000003, 0,
            1080, 768, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 658, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000292, 0x00000004, 0,
            1080, 844, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 659, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000293, 0x00000005, 0,
            1080, 920, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 660, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000294, 0x00000006, 0,
            1080, 996, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 661, 0, dk2::CButton_handleLeftClick_549220, dk2::CButton_handleRightClick_549420, 0, 0, 0x00000295, 0x00000007, 0,
            1080, 1072, 312, 80, 0, 0, 312, 80, 0, NULL, dk2::CButton_render_5322F0, 0x00000000, 0, 0x00000000, 0x00000000, 33
        },
        {
            BT_CClickButton, 622, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x00000051, 0,
            2120, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderExitBtn, 0x00000000, 0, 0x00000000, 0x00000000, 36
        },
        {
            BT_CClickButton, 623, 0, dk2::CButton_handleLeftClick_changeMenu, NULL, 0, 0, 0x00000000, 0x00000050, 0,
            2336, 1688, 192, 192, 0, 0, 192, 192, 0, NULL, dk2::CClickButton_renderApplyBtn, 0x00000000, 0, 0x00000000, 0x00000000, 35
        },

        EngOfButtonList,
    };

    dk2::WindowCfg GameSettings_WinCfg {
        WID_GameSettings, 0, 0, 0, 0, 2560, 1920, 0, 0, 2560, 1920, 0, NULL, dk2::__onMapSelected, 0,
        0, 0, 0, 0, 0, GameSettings_BtnArr, 2
    };
}

dk2::WindowCfg *GameSettings_layout() {
    return &GameSettings_WinCfg;
}

