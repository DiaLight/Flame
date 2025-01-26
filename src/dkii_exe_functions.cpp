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
#include "gog_patch.h"
#include "gog_cfg.h"
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

BOOL __cdecl dk2::parse_command_line(int argc, const char **argv) {
    if(gog::parseCommandLine_patch::isEnabled()) {
        dk2::MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
        dk2::MyResources_instance.video_settings.zbuffer_bitnes = 32;
        dk2::MyResources_instance.video_settings.display_bitnes = 32;
        if (gog::cfg::iBumpmap) {
            dk2::MyResources_instance.video_settings.setBumpMappingEnabled(1);
        }
    }
    MyGame_debugMsg(&MyGame_instance, "Cmd Line: ");
    for (int i = 0; i < argc; ++i) {
        MyGame_debugMsg(&MyGame_instance, "%s ", argv[i]);
    }
    MyGame_debugMsg(&MyGame_instance, "\n");
    _wcsncpy(MyResources_instance.gameCfg.levelName, L"LEVEL", 64);
    const char **cur_token = argv + 1;
    MyResources_instance.gameCfg.levelName[63] = 0;
    MyResources_instance.gameCfg.hasSaveFile = 0;
    MyResources_instance.gameCfg.showMovies = 1;
    for (;*cur_token; ++cur_token) {
        if (!_strcmpi(*cur_token, "-LEVEL")) {  // Plays a level (where X is the level name)
            const char *arg = *++cur_token;
            wchar_t nameBuf[64];
            if (!utf8_to_unicode(arg, nameBuf, 64)) return FALSE;
            wcsncpy(MyResources_instance.gameCfg.levelName, nameBuf, 64);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            MyResources_instance.gameCfg.f124 = 1;
        } else if (!_strcmpi(*cur_token, "-Q")) {  // Combined with the -LEVEL command below, plays in Campaign mode
            MyResources_instance.gameCfg.f124 = 1;
        } else if (!_strcmpi(*cur_token, "-PD")) {
            MyResources_instance.gameCfg.f128 = 1;
        } else if (!_strcmpi(*cur_token, "-DDD")) {
            int arg = atoi(*++cur_token);
            cmd_flag_DDD = 1;
            cmd_flag_DDD_value = arg;
        } else if (!_strcmpi(*cur_token, "-ENGINE")) {
            MyResources_instance.gameCfg.f120 = 1;
        } else if (!_strcmpi(*cur_token, "-SOFTWARE")) {  // Disables Hardware Acceleration
            if ((MyGame_instance.f50D & 0x800000) != 0) {
                MyResources_instance.video_settings.cmd_flag_SOFTWARE = 1;
            }
        } else if (!_strcmpi(*cur_token, "-CHOOSECARD")) {  // Sets Dungeon Keeper 2 to run using your default video card
            int value = getDevIdxSupportsLinearPerspective();
            if (value < 0) {
                MyResources_instance.video_settings.setSelected3dEngine(4);
                MyResources_instance.video_settings.sub_566E40(0);
                MyGame_instance.selected_dd_idx = 0;
            } else {
                MyResources_instance.video_settings.setSelected3dEngine(2);
                MyResources_instance.video_settings.sub_566E40(value);
                MyGame_instance.selected_dd_idx = value;
            }
        } else if (!_strcmpi(*cur_token, "-PLOAD")) {  // Load a packet where X is the name of the file (must be use with -LEVEL command)
            const char *arg1 = *++cur_token;
            int arg2 = atoi(*++cur_token);
            MyResources_instance.packetRecord.loadSavFile((char *) arg1, arg2, 0);
        } else if (!_strcmpi(*cur_token, "-PSAVE")) {  // Record a packet where X is the name of the file (must be use with -LEVEL command)
            const char *arg = *++cur_token;
            MyResources_instance.packetRecord.reopenSavFile((char *) arg);
        } else if (!_strcmpi(*cur_token, "-PQUIT")) {
            int arg = atoi(*++cur_token);
            MyResources_instance.packetRecord.pQuitValue = arg;
        } else if (!_strcmpi(*cur_token, "-PNUMBER")) {
            int arg = atoi(*++cur_token);
            MyResources_instance.packetRecord.pNumberValue = arg;
            MyResources_instance.packetRecord.pUsePnumber = 1;
        } else if (!_strcmpi(*cur_token, "-PNOCAMERA")) {
            MyResources_instance.packetRecord.pUseCamera = 0;
        } else if (!_strcmpi(*cur_token, "-PLOADDEMOKEY")) {
            MyResources_instance.packetRecord.pLoadDemoKey = 1;
        } else if (!_strcmpi(*cur_token, "-NOSOUND")) {
            cmd_flag_NOSOUND = 1;
        } else if (!_strcmpi(*cur_token, "-SOUND")) {
            cmd_flag_NOSOUND = 0;
        } else if (!_strcmpi(*cur_token, "-FPS")) {
            MyResources_instance.gameCfg.useFps2 = 1;
        } else if (!_strcmpi(*cur_token, "-NOFPS")) {
            MyResources_instance.gameCfg.useFps = 1;
        } else if (!_strcmpi(*cur_token, "-SPEC")) {
            int arg = atoi(*++cur_token);
            MyResources_instance.video_settings.setSpec(arg);
        } else if (!_strcmpi(*cur_token, "-NOERRORS")) {
            cmd_flag_NOERRORS = 0;
        } else if (!_strcmpi(*cur_token, "-NOMUSIC")) {
            MyResources_instance.soundCfg.setMusicEnabled(0);
        } else if (!_strcmpi(*cur_token, "-NOSPEECH")) {
            MyResources_instance.soundCfg.setSpeech(0);
        } else if (!_strcmpi(*cur_token, "-NOINTMOUSE")) {  // Disables frame-rate independant mouse pointer
            MyResources_instance.gameCfg.useIntMouse = 0;
        } else if (!_strcmpi(*cur_token, "-32BITDISPLAY")) {  // Enables 32Bit Display (32bit colours instead of 16bit)
            MyResources_instance.video_settings.display_bitnes = 32;
        } else if (!_strcmpi(*cur_token, "-32BITZBUFFER")) {  // Enables 32Bit ZBuffer (32bit ZBuffer instead of 16bit ZBuffer)
            MyResources_instance.video_settings.zbuffer_bitnes = 32;
        } else if (!_strcmpi(*cur_token, "-32BITTEXTURES")) {  // Enables 32Bit Textures
            MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
        } else if (!_strcmpi(*cur_token, "-32BITEVERYTHING")) {  // Enables 32Bit Textures, ZBuffer and Display
            MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
            MyResources_instance.video_settings.zbuffer_bitnes = 32;
            MyResources_instance.video_settings.display_bitnes = 32;
        } else if (!_strcmpi(*cur_token, "-SOFTWAREFILTER")) {  // Enables Software Filter (Bilinear Filtering)
            MyResources_instance.video_settings.cmd_flag_SOFTWAREFILTER = 1;
        } else if (!_strcmpi(*cur_token, "-FE3D")) {  // Defines 3D FrontEnd (?)
            MyResources_instance.gameCfg.useFe3d = 1;
            MyResources_instance.gameCfg.useFe_playMode = 1;
            wcsncpy(MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
            MyResources_instance.gameCfg.useFe2d_unk2 = 0;
            cmd_flag_FrontEnd3D_unk7 = 1;
            cmd_flag_FrontEnd3D_unk8 = 1;
        } else if (!_strcmpi(*cur_token, "-FE")) {  // Defines 2D FrontEnd (I tried and the screen stayed black so, beware!) (?)
            MyResources_instance.gameCfg.useFe3d = 0;
            MyResources_instance.gameCfg.useFe_playMode = 1;
            wcsncpy(MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64);
            MyResources_instance.gameCfg.levelName[63] = 0;
            MyResources_instance.gameCfg.hasSaveFile = 0;
            MyResources_instance.gameCfg.useFe_unkTy = 3;
            MyResources_instance.gameCfg.useFe2d_unk1 = 1;
            MyResources_instance.gameCfg.useFe2d_unk2 = 1;
            cmd_flag_FrontEnd3D_unk7 = 1;
            cmd_flag_FrontEnd3D_unk8 = 1;
        } else if (!_strcmpi(*cur_token, "-NOFILECHECKSUM")) {  // Disables File CheckSum
            MyResources_instance.gameCfg.noFileChecksum = 0;
        } else if (!_strcmpi(*cur_token, "-EHEAP")) {  // Defines Engine Heap Size in Mb
            int arg = atoi(*++cur_token);
            MyResources_instance.gameCfg.heapSizeMb = arg;
        } else if (!_strcmpi(*cur_token, "-DISABLEGAMMA")) {  // Corrects screen tinting and colour corruption caused by the mouse cursor
            MyResources_instance.video_settings.untouched2_eq_1 = 0;
        } else if (!_strcmpi(*cur_token, "-HIGHRESTEXTURES")) {
            MyResources_instance.video_settings.setHighResolutionTexturesEnabled(1);
        } else if (!_strcmpi(*cur_token, "-LOWRESTEXTURES")) {
            MyResources_instance.video_settings.setHighResolutionTexturesEnabled(0);
        } else if (!_strcmpi(*cur_token, "-CHEAPLIGHTING")) {
            MyResources_instance.video_settings.setCheapLightningEnabled(1);
        } else if (
                !_strcmpi(*cur_token, "-ENABLEBUMPMAPPING") ||  // Enables BumpMapping (try it and check the lava)
                !_strcmpi(*cur_token, "-ENABLEBUMPLUMINANCE")) {
            MyResources_instance.video_settings.setBumpMappingEnabled(1u);
        } else if (!_strcmpi(*cur_token, "-TEXTUREREDUCTIONLEVEL")) {
            int arg = atoi(*++cur_token);
            MyResources_instance.video_settings.setTextureReductionLevel(arg);
        } else if (!_strcmpi(*cur_token, "-ENABLEARTPATCHING")) {  // Allows to use the extracted WAD files instead of the compressed ones
            MyResources_instance.gameCfg.EnableArtPatching = 1;
        } else if (!_strcmpi(*cur_token, "-LANGUAGE")) {
            const char *arg = *++cur_token;
            strcpy(MyResources_instance.playerCfg.kbLayoutName, arg);
        } else if (!_strcmpi(*cur_token, "-CDPATH")) {
            const char *arg = *++cur_token;
            MyResources_instance.setCdPath(arg);
        } else if (!_strcmpi(*cur_token, "-NOSHADOWS")) {
            MyResources_instance.video_settings.setShadowsLevel(0);
        } else if (!_strcmpi(*cur_token, "-SHADOWS")) {  // Defines "Shadow Level"
            int arg = atoi(*++cur_token);
            MyResources_instance.video_settings.setShadowsLevel(arg);
        } else if (!_strcmpi(*cur_token, "-NOMOVIES")) {
            MyResources_instance.gameCfg.showMovies = 0;
        } else if (!_strcmpi(*cur_token, "-PRELOADRESOURCES")) {
            MyResources_instance.gameCfg.preloadResources = 1;
        } else if (!_strcmpi(*cur_token, "-CHEAT")) {
            MyResources_instance.gameCfg.useCheats = 1;
        } else if (!_strcmpi(*cur_token, "-NOCHECKSUM")) {  // Disables CheckSum
            MyResources_instance.useChecksum = 0;
        } else if (!_strcmpi(*cur_token, "-PMESH")) {  // Defines "PMesh Reduction Level"
            int arg = atoi(*++cur_token);
            MyResources_instance.video_settings.setPmeshReductionLevel(arg);
        } else if (!_strcmpi(*cur_token, "-LOGOOS")) {  // logging of out of sync
            MyResources_instance.gameCfg.logOos__eos = 1;
        } else if (!_strcmpi(*cur_token, "-ENABLEFILEPATCHING")) {  // Allows to use the extracted WAD files instead of the compressed ones
            MyResources_instance.fillPaths();
        }
    }
    if(patch::force_32bit_everything::enabled) {
        MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
        MyResources_instance.video_settings.zbuffer_bitnes = 32;
        MyResources_instance.video_settings.display_bitnes = 32;
    }
    MyResources_instance.fillPaths();
    MyResources_instance.gameCfg.EnableArtPatching = 1;
    return 1;
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
    WeaNetR_instance.load_player_info();
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
