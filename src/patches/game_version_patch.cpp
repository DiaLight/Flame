//
// Created by DiaLight on 06.08.2024.
//

#include "game_version_patch.h"
#include <Windows.h>
#include <cstdio>

bool patch::game_version_patch::enabled = true;

extern "C" char Flame_version[64] = {'\0', '1'};

char *patch::game_version_patch::getFileVersion() {
    if(!enabled) return nullptr;
    if(Flame_version[0] == '\0') return nullptr;
    return Flame_version;
}
