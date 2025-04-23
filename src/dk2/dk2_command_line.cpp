//
// Created by DiaLight on 4/8/2025.
//
#include <tools/flame_config.h>

#include "dk2/MyGame.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "gog_patch.h"
#include "gog_cfg.h"


flame_config::define_flame_option<std::string> o_dk2_level(
    "dk2:Level",
    "Plays a level (arg is the level name)",
    ""
);
flame_config::define_flame_option<bool> o_dk2_q(
    "dk2:Q",
    "Combined with the -LEVEL command, plays in Campaign mode",
    false
);
flame_config::define_flame_option<bool> o_dk2_pd(
    "dk2:PD",
    "",
    false
);
flame_config::define_flame_option<int> o_dk2_ddd(
    "dk2:DDD",
    "",
    -1
);
flame_config::define_flame_option<bool> o_dk2_engine(
    "dk2:Engine",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_software(
    "dk2:Software",
    "disables hardware acceleration",
    false
);
flame_config::define_flame_option<bool> o_dk2_chooseCard(
    "dk2:ChooseCard",
    "Sets Dungeon Keeper 2 to run using your default video card",
    false
);
flame_config::define_flame_option<std::string> o_dk2_pload(
    "dk2:PLoad",
    "Load a packet where arg is the name of the file (must be use with -LEVEL command)\n"
    "Must be used with dk2:pload-freq option\n",
    ""
);
flame_config::define_flame_option<int> o_dk2_pload_freq(
    "dk2:PLoadFreq",
    "Set renderer frequency\n"
    "Must be used with dk2:pload option\n",
    -1
    );
flame_config::define_flame_option<std::string> o_dk2_psave(
    "dk2:PSave",
    "Must be used with dk2:pload-freq option\n",
    ""
);
flame_config::define_flame_option<int> o_dk2_pquit(
    "dk2:PQuit",
    "",
    -1
);
flame_config::define_flame_option<int> o_dk2_pnumber(
    "dk2:PNumber",
    "",
    -1
);
flame_config::define_flame_option<bool> o_dk2_pNoCamera(
    "dk2:PNoCamera",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_pLoadDemoKey(
    "dk2:PLoadDemoKey",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_pNoSound(
    "dk2:NoSound",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_pSound(
    "dk2:Sound",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_pFps(
    "dk2:Fps",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_pNoFps(
    "dk2:NoFps",
    "",
    false
);
flame_config::define_flame_option<int> o_dk2_pSpec(
    "dk2:Spec",
    "",
    -1
);
flame_config::define_flame_option<bool> o_dk2_noErrors(
    "dk2:NoErrors",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_noMusic(
    "dk2:NoMusic",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_noSpeech(
    "dk2:NoSpeech",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_noIntMouse(
    "dk2:NoIntMouse",
    "Disables frame-rate independant mouse pointer",
    false
);
flame_config::define_flame_option<bool> o_dk2_32BitDisplay(
    "dk2:32BitDisplay",
    "Enables 32Bit Display (32bit colours instead of 16bit)",
    false
);
flame_config::define_flame_option<bool> o_dk2_32BitZBuffer(
    "dk2:32BitZBuffer",
    "Enables 32Bit ZBuffer (32bit ZBuffer instead of 16bit ZBuffer)",
    false
);
flame_config::define_flame_option<bool> o_dk2_32BitTextures(
    "dk2:32BitTextures",
    "Enables 32Bit Textures",
    false
);
flame_config::define_flame_option<bool> o_dk2_32BitEverything(
    "dk2:32BitEverything",
    "Enables 32Bit Textures, ZBuffer and Display",
    false
);
flame_config::define_flame_option<bool> o_dk2_softwareFilter(
    "dk2:SoftwareFilter",
    "Enables Software Filter (Bilinear Filtering)",
    false
);
flame_config::define_flame_option<bool> o_dk2_fe3d(
    "dk2:FE3d",
    "Defines 3D FrontEnd (?)",
    false
);
flame_config::define_flame_option<bool> o_dk2_fe(
    "dk2:FE",
    "Defines 2D FrontEnd (I tried and the screen stayed black so, beware!) (?)",
    false
);
flame_config::define_flame_option<bool> o_dk2_noFileChecksum(
    "dk2:NoFileChecksum",
    "Disables File CheckSum",
    false
);
flame_config::define_flame_option<int> o_dk2_eheap(
    "dk2:EHeap",
    "Defines Engine Heap Size in Mb",
    -1
);
flame_config::define_flame_option<bool> o_dk2_disableGamma(
    "dk2:DisableGamma",
    "Corrects screen tinting and colour corruption caused by the mouse cursor",
    false
);
flame_config::define_flame_option<bool> o_dk2_highResTextures(
    "dk2:HighResTextures",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_lowResTextures(
    "dk2:LowResTextures",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_cheapLightning(
    "dk2:CheapLightning",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_enableBumpMapping(
    "dk2:EnableBumpMapping",
    "Enables BumpMapping (try it and check the lava)",
    false
);
flame_config::define_flame_option<bool> o_dk2_enableBumpLuminance(
    "dk2:EnableBumpLuminance",
    "",
    false
);
flame_config::define_flame_option<int> o_dk2_textureReductionLevel(
    "dk2:TextureReductionLevel",
    "",
    -1
);
flame_config::define_flame_option<bool> o_dk2_enableArtPatching(
    "dk2:EnableArtPatching",
    "Allows to use the extracted WAD files instead of the compressed ones",
    false
);
flame_config::define_flame_option<std::string> o_dk2_language(
    "dk2:Language",
    "",
    ""
);
flame_config::define_flame_option<std::string> o_dk2_cdPath(
    "dk2:CdPath",
    "",
    ""
);
flame_config::define_flame_option<bool> o_dk2_noShadows(
    "dk2:NoShadows",
    "",
    false
);
flame_config::define_flame_option<int> o_dk2_shadows(
    "dk2:Shadows",
    "Defines \"Shadow Level\"",
    -1
);
flame_config::define_flame_option<bool> o_dk2_noMovies(
    "dk2:NoMovies",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_preloadResources(
    "dk2:PreloadResources",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_cheat(
    "dk2:Cheat",
    "",
    false
);
flame_config::define_flame_option<bool> o_dk2_noChecksum(
    "dk2:NoChecksum",
    "",
    false
);
flame_config::define_flame_option<int> o_dk2_pmesh(
    "dk2:PMesh",
    "Defines \"PMesh Reduction Level\"",
    -1
);
flame_config::define_flame_option<bool> o_dk2_logOos(
    "dk2:LogOOS",
    "logging of out of sync",
    false
);
flame_config::define_flame_option<bool> o_dk2_enableFilePatching(
    "dk2:EnableFilePatching",
    "Allows to use the extracted WAD files instead of the compressed ones",
    false
);


namespace patch::replace_parse_command_line {

    bool enabled = true;
    bool parse() {
        if (!o_dk2_level->empty()) {
            std::string &arg = *o_dk2_level;
            wchar_t nameBuf[64];
            if (!dk2::utf8_to_unicode(arg.c_str(), nameBuf, 64)) return false;
            wcsncpy(dk2::MyResources_instance.gameCfg.levelName, nameBuf, 64);
            dk2::MyResources_instance.gameCfg.levelName[63] = 0;
            dk2::MyResources_instance.gameCfg.hasSaveFile = 0;
            dk2::MyResources_instance.gameCfg.f124 = 1;
        }
        if (*o_dk2_q) {
            dk2::MyResources_instance.gameCfg.f124 = 1;
        }
        if (*o_dk2_pd) {
            dk2::MyResources_instance.gameCfg.f128 = 1;
        }
        if (*o_dk2_ddd >= 0) {
            int arg = *o_dk2_ddd;
            dk2::cmd_flag_DDD = 1;
            dk2::cmd_flag_DDD_value = arg;
        }
        if (*o_dk2_engine) {
            dk2::MyResources_instance.gameCfg.f120 = 1;
        }
        if (*o_dk2_software) {
            if ((dk2::MyGame_instance.f50D & 0x800000) != 0) {
                dk2::MyResources_instance.video_settings.cmd_flag_SOFTWARE = 1;
            }
        }
        if (*o_dk2_chooseCard) {
            int value = dk2::getDevIdxSupportsLinearPerspective();
            if (value < 0) {
                dk2::MyResources_instance.video_settings.setSelected3dEngine(4);
                dk2::MyResources_instance.video_settings.writeGuidIndex(0);
                dk2::MyGame_instance.selected_dd_idx = 0;
            } else {
                dk2::MyResources_instance.video_settings.setSelected3dEngine(2);
                dk2::MyResources_instance.video_settings.writeGuidIndex(value);
                dk2::MyGame_instance.selected_dd_idx = value;
            }
        }
        if (!o_dk2_pload->empty() && *o_dk2_pload_freq >= 0) {
            std::string &arg1 = *o_dk2_pload;
            int arg2 = *o_dk2_pload_freq;
            dk2::MyResources_instance.packetRecord.loadSavFile((char *) arg1.c_str(), arg2, 0);
        }
        if (!o_dk2_psave->empty()) {
            std::string &arg = *o_dk2_psave;
            dk2::MyResources_instance.packetRecord.reopenSavFile((char *) arg.c_str());
        }
        if (*o_dk2_pquit >= 0) {
            int arg = *o_dk2_pquit;
            dk2::MyResources_instance.packetRecord.pQuitValue = arg;
        }
        if (*o_dk2_pnumber >= 0) {
            int arg = *o_dk2_pnumber;
            dk2::MyResources_instance.packetRecord.pNumberValue = arg;
            dk2::MyResources_instance.packetRecord.pUsePnumber = 1;
        }
        if (*o_dk2_pNoCamera) {
            dk2::MyResources_instance.packetRecord.pUseCamera = 0;
        }
        if (*o_dk2_pLoadDemoKey) {
            dk2::MyResources_instance.packetRecord.pLoadDemoKey = 1;
        }
        if (*o_dk2_pNoSound) {
            dk2::cmd_flag_NOSOUND = 1;
        }
        if (*o_dk2_pSound) {
            dk2::cmd_flag_NOSOUND = 0;
        }
        if (*o_dk2_pFps) {
            dk2::MyResources_instance.gameCfg.useFps2 = 1;
        }
        if (*o_dk2_pNoFps) {
            dk2::MyResources_instance.gameCfg.useFps = 1;
        }
        if (*o_dk2_pSpec >= 0) {
            int arg = *o_dk2_pSpec;
            dk2::MyResources_instance.video_settings.setSpec(arg);
        }
        if (*o_dk2_noMusic) {
            dk2::MyResources_instance.soundCfg.saveMusicEnabled(0);
        }
        if (*o_dk2_noErrors) {
            dk2::cmd_flag_NOERRORS = 0;
        }
        if (*o_dk2_noSpeech) {
            dk2::MyResources_instance.soundCfg.saveSpeech(0);
        }
        if (*o_dk2_noIntMouse) {
            dk2::MyResources_instance.gameCfg.useIntMouse = 0;
        }
        if (*o_dk2_32BitDisplay) {
            dk2::MyResources_instance.video_settings.display_bitnes = 32;
        }
        if (*o_dk2_32BitZBuffer) {
            dk2::MyResources_instance.video_settings.zbuffer_bitnes = 32;
        }
        if (*o_dk2_32BitTextures) {
            dk2::MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
        }
        if (*o_dk2_32BitEverything) {
            dk2::MyResources_instance.video_settings.cmd_flag_32BITTEXTURES = 1;
            dk2::MyResources_instance.video_settings.zbuffer_bitnes = 32;
            dk2::MyResources_instance.video_settings.display_bitnes = 32;
        }
        if (*o_dk2_softwareFilter) {
            dk2::MyResources_instance.video_settings.cmd_flag_SOFTWAREFILTER = 1;
        }
        if (*o_dk2_fe3d) {
            dk2::MyResources_instance.gameCfg.useFe3d = 1;
            dk2::MyResources_instance.gameCfg.useFe_playMode = 1;
            wcsncpy(dk2::MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64);
            dk2::MyResources_instance.gameCfg.levelName[63] = 0;
            dk2::MyResources_instance.gameCfg.hasSaveFile = 0;
            dk2::MyResources_instance.gameCfg.useFe_unkTy = 3;
            dk2::MyResources_instance.gameCfg.useFe2d_unk2 = 0;
            dk2::cmd_flag_FrontEnd3D_unk7 = 1;
            dk2::cmd_flag_FrontEnd3D_unk8 = 1;
        }
        if (*o_dk2_fe) {
            dk2::MyResources_instance.gameCfg.useFe3d = 0;
            dk2::MyResources_instance.gameCfg.useFe_playMode = 1;
            wcsncpy(dk2::MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64);
            dk2::MyResources_instance.gameCfg.levelName[63] = 0;
            dk2::MyResources_instance.gameCfg.hasSaveFile = 0;
            dk2::MyResources_instance.gameCfg.useFe_unkTy = 3;
            dk2::MyResources_instance.gameCfg.useFe2d_unk1 = 1;
            dk2::MyResources_instance.gameCfg.useFe2d_unk2 = 1;
            dk2::cmd_flag_FrontEnd3D_unk7 = 1;
            dk2::cmd_flag_FrontEnd3D_unk8 = 1;
        }
        if (*o_dk2_noFileChecksum) {
            dk2::MyResources_instance.gameCfg.noFileChecksum = 0;
        }
        if (*o_dk2_eheap >= 0) {
            int arg = *o_dk2_eheap;
            dk2::MyResources_instance.gameCfg.heapSizeMb = arg;
        }
        if (*o_dk2_disableGamma) {
            dk2::MyResources_instance.video_settings.untouched2_eq_1 = 0;
        }
        if (*o_dk2_highResTextures) {
            dk2::MyResources_instance.video_settings.setHighResolutionTexturesEnabled(1);
        }
        if (*o_dk2_lowResTextures) {
            dk2::MyResources_instance.video_settings.setHighResolutionTexturesEnabled(0);
        }
        if (*o_dk2_cheapLightning) {
            dk2::MyResources_instance.video_settings.setCheapLightningEnabled(1);
        }
        if (*o_dk2_enableBumpMapping || *o_dk2_enableBumpLuminance) {
            dk2::MyResources_instance.video_settings.setBumpMappingEnabled(1u);
        }
        if (*o_dk2_textureReductionLevel >= 0) {
            int arg = *o_dk2_textureReductionLevel;
            dk2::MyResources_instance.video_settings.setTextureReductionLevel(arg);
        }
        if (*o_dk2_enableArtPatching) {
            dk2::MyResources_instance.gameCfg.EnableArtPatching = 1;
        }
        if (!o_dk2_language->empty()) {
            const std::string& arg = *o_dk2_language;
            strcpy(dk2::MyResources_instance.playerCfg.kbLayoutName, arg.c_str());
        }
        if (!o_dk2_cdPath->empty()) {
            const std::string& arg = *o_dk2_cdPath;
            dk2::MyResources_instance.setCdPath(arg.c_str());
        }
        if (*o_dk2_noShadows) {
            dk2::MyResources_instance.video_settings.setShadowsLevel(0);
        }
        if (*o_dk2_shadows >= 0) {
            int arg = *o_dk2_shadows;
            dk2::MyResources_instance.video_settings.setShadowsLevel(arg);
        }
        if (*o_dk2_noMovies) {
            dk2::MyResources_instance.gameCfg.showMovies = 0;
        }
        if (*o_dk2_preloadResources) {
            dk2::MyResources_instance.gameCfg.preloadResources = 1;
        }
        if (*o_dk2_cheat) {
            dk2::MyResources_instance.gameCfg.useCheats = 1;
        }
        if (*o_dk2_noChecksum) {
            dk2::MyResources_instance.useChecksum = 0;
        }
        if (*o_dk2_pmesh >= 0) {
            int arg = *o_dk2_pmesh;
            dk2::MyResources_instance.video_settings.setPmeshReductionLevel(arg);
        }
        if (*o_dk2_logOos) {
            dk2::MyResources_instance.gameCfg.logOos__eos = 1;
        }
        if (*o_dk2_enableFilePatching) {
            dk2::MyResources_instance.fillPaths();
        }
        return true;
    }

}

namespace dk2 {

    bool parse_command_line_original(int argc, const char **argv) {
        const char **cur_token = argv + 1;
        for (;*cur_token; ++cur_token) {
            if (!_strcmpi(*cur_token, "-LEVEL")) {  // Plays a level (where X is the level name)
                const char *arg = *++cur_token;
                wchar_t nameBuf[64];
                if (!utf8_to_unicode(arg, nameBuf, 64)) return false;
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
                    MyResources_instance.video_settings.writeGuidIndex(0);
                    MyGame_instance.selected_dd_idx = 0;
                } else {
                    MyResources_instance.video_settings.setSelected3dEngine(2);
                    MyResources_instance.video_settings.writeGuidIndex(value);
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
                MyResources_instance.soundCfg.saveMusicEnabled(0);
            } else if (!_strcmpi(*cur_token, "-NOSPEECH")) {
                MyResources_instance.soundCfg.saveSpeech(0);
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
        return true;
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
    MyResources_instance.gameCfg.levelName[63] = 0;
    MyResources_instance.gameCfg.hasSaveFile = 0;
    MyResources_instance.gameCfg.showMovies = 1;

    if (patch::replace_parse_command_line::enabled) {
        if (!patch::replace_parse_command_line::parse()) return FALSE;
    } else {
        if (!parse_command_line_original(argc, argv)) return FALSE;
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

