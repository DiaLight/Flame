//
// Created by DiaLight on 01.07.2024.
//
#include "dk2/MyGame.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/button/CTextBox.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "patches/game_version_patch.h"
#include "weanetr_dll/MLDPlay.h"


int32_t dk2::MyGame::isOsCompatible() {
    if(patch::modern_windows_support::enabled) {
        return !dk2::isOsVersionGE(11, 0, 0);
    }
    return !isOsVersionGE(6, 0, 0);
}

void dk2::resolveDk2HomeDir() {
    if(patch::use_cwd_as_dk2_home_dir::enabled) {
        char tmp[MAX_PATH];
        DWORD len = GetCurrentDirectoryA(MAX_PATH, tmp);
        strcpy(tmp + len, "\\");
//        printf("replace exe dir path1: %s -> %s\n", dk2::dk2HomeDir, tmp);
        strcpy(dk2::dk2HomeDir, tmp);
        return;
    }
    const char *CommandLineA = GetCommandLineA();
    _strncpy(pathBuf, CommandLineA, 259u);
    char firstChar = pathBuf[0];
    pathBuf[259] = 0;
    char sepChar = ' ';
    if ( pathBuf[0] == '"' ) {
        signed int idx = 0;
        sepChar = '"';
        unsigned int len = strlen(pathBuf) + 1;
        if ( (int)(len - 1) > 0 ) {
            do {
                pathBuf[idx] = pathBuf[idx + 1];
                ++idx;
            } while ( idx < (int)(len - 1) );
            firstChar = pathBuf[0];
        }
    }
    char *pos = pathBuf;
    if ( firstChar ) {
        char curChar = firstChar;
        do
        {
            if ( curChar == sepChar )
                break;
            curChar = *++pos;
        }
        while ( curChar );
    }
    *pos = 0;
    char *sep1Pos = strrchr(pathBuf, '/');
    char *sep2Pos = strrchr(pathBuf, '\\');
    char **pSepPos = &sep2Pos;
    if ( sep2Pos <= sep1Pos ) pSepPos = &sep1Pos;
    char *sepPos = *pSepPos;
    if ( sepPos ) {
        sepPos[1] = 0;
        setExeDirPath(pathBuf);
    }
}


void __cdecl dk2::CTextBox_renderVersion(dk2::CTextBox *textBox, CFrontEndComponent *frontend) {
    AABB area;
    textBox->getScreenAABB(&area);
    AABB scaled;
    scaled = *frontend->cgui_manager.scaleAabb(&scaled, &area);

    uint8_t __buf[sizeof(MyTextRenderer)];
    MyTextRenderer &renderer = *(MyTextRenderer *) &__buf;
    renderer.constructor();
    int status;
    renderer.selectMyCR(&status, 0);
    renderer.selectMyTR(&status, 2);
    wchar_t wstring[64];
    if(char *version = patch::game_version_patch::getFileVersion()) {
        swprintf(wstring, L"%S", version);
    } else {
        swprintf(wstring, L"V%lu.%lu", g_majorVersion, g_minorVersion);
    }
    uint8_t mbstring[64];
    MyLangObj_static_toUniToMB_2(wstring, mbstring, 64);
    renderer.renderText(&status, &scaled, mbstring, &g_FontObj2_instance, NULL);
    renderer.destructor();
}

int __cdecl dk2::cmd_dumpPlayer(int a1, int a2) {
    WeaNetR_instance.getPlayerInfo();
    if ( *(DWORD *)(a2 + 28) >= WeaNetR_instance.joinedPlayersCount ) {
        ProbablyConsole_instance.appendOutput("Invaliud Player");
        return 1;
    } else {
        // DestroySession
        if ( WeaNetR_instance.mldplay->DumpPlayer(*(DWORD *)(a2 + 28)) )
            ProbablyConsole_instance.appendOutput("Player Dumped");
        else
            ProbablyConsole_instance.appendOutput("Error!");
        return 1;
    }
}

int dk2::cmd_Game() {  // there should be args
    char msgData = 0x63;
    if (!WeaNetR_instance.sendGuaranteedData(&msgData, 1u, 0xFFFFu)) {
        ProbablyConsole_instance.appendOutput("Unable to Send Guaranteed Data");
        return 0;
    }
    ProbablyConsole_instance.appendOutput("Send Guaranteed Data success");
    WeaNetR_instance.mldplay->EnableNewPlayers(0);
    return 1;
}
