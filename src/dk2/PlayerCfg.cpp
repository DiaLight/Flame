//
// Created by DiaLight on 09.08.2024.
//
#include <map>
#include "dk2/PlayerCfg.h"
#include "dk2/KeyEntry.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "dk2_functions.h"


enum Dk2Key {
    Key_ZoomIn = 14,  // home
    Key_ZoomOut = 15,  // end
    Key_MoveUp = 16,  // up
    Key_MoveDown = 17,  // down
    Key_MoveLeft = 18,  // left
    Key_MoveRight = 19,  // right

    Key_RotateLeft = 22,  // del
    Key_RotateRight = 23,  // pgdn

    Key_ToggleAllyWindow = 36,  // A

    Key_PitchUp = 47,  // ctrl + home
    Key_PitchDown = 48,  // ctrl + end

    Key_RollLeft = 49,  // ctrl + Insert
    Key_RollRight = 50,  // ctrl + delete

    Key_YawLeft = 51,  // ctrl + pgup
    Key_YawRight = 52,  // ctrl + pgdn
};

enum Dk2KeyModifier {
    Mod_Shift = 1,
    Mod_Ctrl = 2,
    Mod_Alt = 4,
};

std::map<int, dk2::DxKeyEntry> defaultKeyTable = {
        {1,               {DIK_INSERT,   0}},  // 1: 0xD2
        {2,               {DIK_NUMPAD0,  0}},  // 2: 0x52
        {3,               {DIK_SPACE,    0}},  // 3: 0x39
        {4,               {DIK_RCONTROL, 0}},  // 4: 0x9D
        {5,               {DIK_RSHIFT,   0}},  // 5: 0x36
        {6,               {DIK_1,        0}},  // 6: 2
        {7,               {DIK_2,        0}},  // 7: 3
        {8,               {DIK_3,        0}},  // 8: 4
        {9,               {DIK_4,        0}},  // 9: 5
        {10,              {DIK_5,        0}},  // 10: 6
        {11,              {DIK_6,        0}},  // 11: 7
        {12,              {DIK_7,        0}},  // 12: 8
        {13,              {DIK_G,        Mod_Ctrl}},  // 13: 0x22 + 2
        {Key_ZoomIn,      {DIK_HOME,     0}},  // 14: 0xC7
        {Key_ZoomOut,     {DIK_END,      0}},  // 15: 0xCF
        {Key_MoveUp,      {DIK_UP,       0}},  // 16: 0xC8
        {Key_MoveDown,    {DIK_DOWN,     0}},  // 17: 0xD0
        {Key_MoveLeft,    {DIK_LEFT,     0}},  // 18: 0xCB
        {Key_MoveRight,   {DIK_RIGHT,    0}},  // 19: 0xCD
        {20,              {DIK_LCONTROL, 0}},  // 20: 0x1D
        {21,              {DIK_LSHIFT,   0}},  // 21: 0x2A
        {Key_RotateLeft,  {DIK_DELETE,   0}},  // 22: 0xD3
        {Key_RotateRight, {DIK_PGDN,     0}},  // 23: 0xD1
        {24,              {DIK_ESCAPE,   0}},  // 24: 1
        {25,              {DIK_SYSRQ,    0}},  // 25: 0xB7
        {26,              {DIK_PGUP,     0}},  // 26: 0xC9
        {27,              {DIK_TAB,      0}},  // 27: 0xF
        {28,              {DIK_EQUALS,   0}},  // 28: 0xD  Japanese Keyboard case f0_dxKey=0x90
        {29,              {DIK_MINUS,    0}},  // 29: 0xC
        {30,              {DIK_F1,       0}},  // 30: 0x3B
        {31,              {DIK_F2,       0}},  // 31: 0x3C
        {32,              {DIK_F3,       0}},  // 32: 0x3D
        {33,              {DIK_F4,       0}},  // 33: 0x3E
        {34,              {DIK_F5,       0}},  // 34: 0x3F
        {35,              {DIK_F6,       0}},  // 35: 0x40
        {Key_ToggleAllyWindow, {DIK_A,        0}},  // 36: 0x1E
        {37,              {DIK_F,        0}},  // 37: 0x21
        {38,              {DIK_G,        0}},  // 38: 0x22
        {39,              {DIK_H,        0}},  // 39: 0x23
        {40,              {DIK_I,        0}},  // 40: 0x17
        {41,              {DIK_M,        0}},  // 41: 0x32
        {42,              {DIK_P,        0}},  // 42: 0x19
        {43,              {DIK_X,        0}},  // 43: 0x2D
        {44,              {DIK_Z,        0}},  // 44: 0x2C
        {45,              {DIK_PERIOD,   Mod_Shift}},  // 45: 0x34 + 1
        {46,              {DIK_COMMA,    Mod_Shift}},  // 46: 0x33 + 1
        {Key_PitchUp,     {DIK_HOME,     Mod_Ctrl}},  // 47: 0xC7 + 2
        {Key_PitchDown,   {DIK_END,      Mod_Ctrl}},  // 48: 0xCF + 2
        {Key_RollLeft,    {DIK_INSERT,   Mod_Ctrl}},  // 49: 0xD2 + 2
        {Key_RollRight,   {DIK_DELETE,   Mod_Ctrl}},  // 50: 0xD3 + 2
        {Key_YawLeft,     {DIK_PGUP,     Mod_Ctrl}},  // 51: 0xC9 + 2
        {Key_YawRight,    {DIK_PGDN,     Mod_Ctrl}},  // 52: 0xD1 + 2
        {53,              {DIK_PERIOD,   Mod_Ctrl}},  // 53: 0x34 + 2
        {54,              {DIK_COMMA,    Mod_Ctrl}},  // 54: 0x33 + 2
        {55,              {DIK_L,        Mod_Ctrl}},  // 55: 0x26 + 2
        {56,              {DIK_S,        Mod_Ctrl}},  // 56: 0x1F + 2
        {57,              {DIK_R,        Mod_Ctrl}},  // 57: 0x13 + 2
        {58,              {DIK_A,        Mod_Alt}},  // 58: 0x1E + 4
        {59,              {DIK_1,        Mod_Alt}},  // 59: 2 + 4
        {60,              {DIK_2,        Mod_Alt}},  // 60: 3 + 4
        {61,              {DIK_3,        Mod_Alt}},  // 61: 4 + 4
        {62,              {DIK_4,        Mod_Alt}},  // 62: 5 + 4
        {63,              {DIK_P,        Mod_Ctrl}},  // 63: 0x19 + 2
};

void dk2::PlayerCfg::fillKeyMaps() {
    memset(this->actionToDxKey, 0, sizeof(this->actionToDxKey));
    this->actionToDxKey[1].dxKey = 0xD2;
    this->actionToDxKey[25].dxKey = 0xB7;
    this->actionToDxKey[28].dxKey = 0xD;
    if ( GetKeyboardType(0) == 7 && (GetKeyboardType(1) == 2 || (GetKeyboardType(1) & 0xFF00) == 0xD00) )
        this->actionToDxKey[28].dxKey = 0x90;  // Japanese Keyboard case
    this->actionToDxKey[29].dxKey = 0xC;
    this->actionToDxKey[6].dxKey = 2;
    this->actionToDxKey[7].dxKey = 3;
    this->actionToDxKey[8].dxKey = 4;
    this->actionToDxKey[9].dxKey = 5;
    this->actionToDxKey[2].dxKey = 0x52;
    this->actionToDxKey[10].dxKey = 6;
    this->actionToDxKey[11].dxKey = 7;
    this->actionToDxKey[13].dxKey = 0x22;
    this->actionToDxKey[13].modifierFlags = 2;
    this->actionToDxKey[4].dxKey = 0x9D;
    this->actionToDxKey[5].dxKey = 0x36;
    this->actionToDxKey[3].dxKey = 0x39;
    this->actionToDxKey[38].dxKey = 0x22;
    this->actionToDxKey[39].dxKey = 0x23;
    this->actionToDxKey[45].dxKey = 0x34;
    this->actionToDxKey[45].modifierFlags = 1;
    this->actionToDxKey[46].dxKey = 0x33;
    this->actionToDxKey[46].modifierFlags = 1;
    this->actionToDxKey[56].dxKey = 0x1F;
    this->actionToDxKey[56].modifierFlags = 2;
    this->actionToDxKey[55].dxKey = 0x26;
    this->actionToDxKey[55].modifierFlags = 2;
    this->actionToDxKey[57].dxKey = 0x13;
    this->actionToDxKey[57].modifierFlags = 2;
    this->actionToDxKey[30].dxKey = 0x3B;
    this->actionToDxKey[31].dxKey = 0x3C;
    this->actionToDxKey[41].dxKey = 0x32;
    this->actionToDxKey[32].dxKey = 0x3D;
    this->actionToDxKey[14].dxKey = 0xC7;
    this->actionToDxKey[15].dxKey = 0xCF;
    this->actionToDxKey[22].dxKey = 0xD3;
    this->actionToDxKey[23].dxKey = 0xD1;
    this->actionToDxKey[20].dxKey = 0x1D;
    this->actionToDxKey[21].dxKey = 0x2A;
    this->actionToDxKey[16].dxKey = 0xC8;
    this->actionToDxKey[17].dxKey = 0xD0;
    this->actionToDxKey[18].dxKey = 0xCB;
    this->actionToDxKey[19].dxKey = 0xCD;
    this->actionToDxKey[43].dxKey = 0x2D;
    this->actionToDxKey[44].dxKey = 0x2C;
    this->actionToDxKey[47].dxKey = 0xC7;
    this->actionToDxKey[47].modifierFlags = 2;
    this->actionToDxKey[48].dxKey = 0xCF;
    this->actionToDxKey[48].modifierFlags = 2;
    this->actionToDxKey[49].dxKey = 0xD2;
    this->actionToDxKey[49].modifierFlags = 2;
    this->actionToDxKey[50].dxKey = 0xD3;
    this->actionToDxKey[51].dxKey = 0xC9;
    this->actionToDxKey[52].dxKey = 0xD1;
    this->actionToDxKey[26].dxKey = 0xC9;
    this->actionToDxKey[50].modifierFlags = 2;
    this->actionToDxKey[51].modifierFlags = 2;
    this->actionToDxKey[52].modifierFlags = 2;
    this->actionToDxKey[37].dxKey = 0x21;
    this->actionToDxKey[24].dxKey = 1;
    this->actionToDxKey[33].dxKey = 0x3E;
    this->actionToDxKey[34].dxKey = 0x3F;
    this->actionToDxKey[35].dxKey = 0x40;
    this->actionToDxKey[40].dxKey = 0x17;
    this->actionToDxKey[42].dxKey = 0x19;
    this->actionToDxKey[54].dxKey = 0x33;
    this->actionToDxKey[54].modifierFlags = 2;
    this->actionToDxKey[53].dxKey = 0x34;
    this->actionToDxKey[53].modifierFlags = 2;
    this->actionToDxKey[36].dxKey = 0x1E;
    this->actionToDxKey[27].dxKey = 0xF;
    this->actionToDxKey[12].dxKey = 8;
    this->actionToDxKey[58].dxKey = 0x1E;
    this->actionToDxKey[58].modifierFlags = 4;
    this->actionToDxKey[59].dxKey = 2;
    this->actionToDxKey[59].modifierFlags = 4;
    this->actionToDxKey[60].dxKey = 3;
    this->actionToDxKey[60].modifierFlags = 4;
    this->actionToDxKey[61].dxKey = 4;
    this->actionToDxKey[61].modifierFlags = 4;
    this->actionToDxKey[62].modifierFlags = 4;
    this->actionToDxKey[63].modifierFlags = 2;
    this->actionToDxKey[62].dxKey = 5;
    this->actionToDxKey[63].dxKey = 0x19;

    if(use_wasd_by_default_patch::enabled) {
        this->actionToDxKey[Key_ToggleAllyWindow].dxKey = DIK_Y;  // was at DIK_A
        this->actionToDxKey[Key_MoveUp].dxKey = DIK_W;
        this->actionToDxKey[Key_MoveLeft].dxKey = DIK_A;
        this->actionToDxKey[Key_MoveDown].dxKey = DIK_S;
        this->actionToDxKey[Key_MoveRight].dxKey = DIK_D;
        this->actionToDxKey[Key_RotateLeft].dxKey = DIK_E;
        this->actionToDxKey[Key_RotateRight].dxKey = DIK_Q;
    }

    memset(this->idxToKey_map, 0, sizeof(this->idxToKey_map));
    for (KeyEntry *e = g_keyMap; e->idx; ++e) {
        this->idxToKey_map[e->idx] = e->key;
    }
}
