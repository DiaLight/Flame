//
// Created by DiaLight on 08.07.2024.
//
#include "dk2/MyResources.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"


dk2::MyResources *dk2::MyResources::init_resources() {
    this->meshesFileMan.constructor();
    int v9 = '\b';
    this->devMeshesFileMan.constructor();
    this->engineTexturesFileMan.constructor();
    this->textureFileMan.constructor();
    this->editorFileMan.constructor();
    this->paletteFileMan.constructor();
    this->spriteFileMan.constructor();
    this->textsFileMan.constructor();
    this->pathsFileMan.constructor();
    this->frontEndFileMan.constructor();
    this->f0 = '\0';
    v9 = (uint8_t) 9;
    char exeDir[260];
    _strcpy(exeDir, "D:\\DEV\\DK2\\");
    char *CommandLineA = GetCommandLineA();
    char *cmdl = CommandLineA;
    char *str_end;
    if (*CommandLineA == '"') {
        cmdl = CommandLineA + 1;
        str_end = strchr(CommandLineA + 1, '"');
        goto LABEL_5;
    }
    str_end = strchr(CommandLineA + 1, ' ');
    if (!str_end) {
        str_end = &cmdl[strlen(cmdl)];
        LABEL_5:
        if ( !str_end ) goto LABEL_12;
    }
    if (str_end > cmdl) {
        do {
            if ( *str_end == '\\' ) break;
            --str_end;
        } while( str_end > cmdl );
        if (str_end > cmdl) str_end[1] = '\0';
    }
    _strcpy(exeDir, cmdl);
    LABEL_12:
    if(patch::use_cwd_as_dk2_home_dir::enabled) {
        GetCurrentDirectoryA(MAX_PATH, exeDir);
        strcat(exeDir, "\\");
//        printf("replace exe dir path2: %s -> %s\n", cmdl, exeDir);
    }
    MyGame_debugMsg(&MyGame_instance, "HD Path: %s\n", exeDir);
    _strcpy(this->executableDir, exeDir);
    this->resolveMovies();
    sprintf(this->editorDir, "%sdata\\editor\\", this->executableDir);
    sprintf(this->savesDir, "%sdata\\Save\\", this->executableDir);
    sprintf(this->settingsDir, "%sdata\\Settings\\", this->executableDir);
    sprintf(this->globalDir, "GLOBAL\\");
    sprintf(this->textsDir, "%sdata\\Text\\", this->executableDir);
    sprintf(this->textureCacheDir, "%s\\Dk2TextureCache", this->executableDir);
    sprintf(this->soundSfxDir, "%sdata\\sound\\SFX\\", this->executableDir);
    sprintf(this->soundMusicDir, "%sdata\\sound\\Music\\", this->executableDir);
    uint32_t status;
    CFileManager_readAndParseWad(&status, &this->meshesFileMan, "%sdata\\Meshes.Wad", this->executableDir);
    CFileManager_readAndParseWad(&status, &this->devMeshesFileMan, "K:\\DK2\\Dev\\Data\\Meshes.Wad", this->executableDir);
    CFileManager_readAndParseWad(&status, &this->engineTexturesFileMan, "%sdata\\EngineTextures.wad", this->executableDir);
    CFileManager_readAndParseWad(&status, &this->spriteFileMan, "%sdata\\Sprite.Wad", this->executableDir);
    CFileManager_readAndParseWad(&status, &this->frontEndFileMan, "%sdata\\FrontEnd.wad", this->executableDir);
    CFileManager_readAndParseWad(&status, &this->pathsFileMan, "%sdata\\Paths.wad", this->executableDir);
    CFileManager_setPathFormat(&status, &this->editorFileMan, "%sdata\\editor", this->executableDir);
    CFileManager_setPathFormat(&status, &this->textsFileMan, "%sdata\\text\\", this->executableDir);
    CFileManager_setPathFormat(&status, &this->textureFileMan, "%sdata\\Texture", this->executableDir);
    CFileManager_setPathFormat(&status, &this->paletteFileMan, "%sdata\\palette", this->executableDir);
    return this;
}
