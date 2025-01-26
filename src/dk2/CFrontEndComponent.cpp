//
// Created by DiaLight on 21.07.2024.
//
#include <dk2/CFrontEndComponent.h>
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"


void dk2::CFrontEndComponent::showTitleScreen() {
    char Buffer[260];
    if (MyResources_instance.playerCfg.kbLayoutId == 17 ) {
        sprintf(Buffer, "TitleScreen\\TitleScreen-Japanese");
    } else {
        char *LayoutName = MyResources_instance.playerCfg.getLayoutName();
        sprintf(Buffer, "TitleScreen\\TitleScreen");
        if ( _strcmpi(LayoutName, "english") )
            sprintf(Buffer, "TitleScreen\\TitleScreen-%s", LayoutName);
    }
    unsigned __int16 extensionFlags = getResourceExtensionFlags();
    int status;
    loadArtToSurfaceEx(
            &status,
            &this->titleScreen,
            &MyResources_instance.frontEndFileMan,
            Buffer,
            extensionFlags);
    if ( status >= 0 ) {
        static_MyDdSurfaceEx_BltWait(&status, this->pMyDdSurfaceEx, 0, 0, &this->titleScreen, 0, 0);
        MyGame_instance.prepareScreen();
        if ( MyDdSurface_addRef(&this->titleScreen.dd_surf, 0) )
            MyDdSurface_release(&status, &this->titleScreen.dd_surf);

        if(!patch::skippable_title_screen::enabled) {
            DWORD waitEnd = getTimeMs() + 10000;
            while ( getTimeMs() <= waitEnd ) ;
        } else {
            DWORD waitEnd = getTimeMs() + patch::skippable_title_screen::waiting_time;
            while ( getTimeMs() <= waitEnd && !patch::skippable_title_screen::skipKeyPressed() ) ;
        }
        MyGame_instance.prepareScreen();
    }
}
