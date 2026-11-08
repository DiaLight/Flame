//
// Created by DiaLight on 1/9/2026.
//
#include <dk2/components/CEntryComponent.h>
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/logging.h"

dk2::CComponent *dk2::CEntryComponent::runUntilDestroy() {
    patch::log::dbg("enter CEntryComponent");
    while (!this->is_component_destroy) {
        MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(&this->static_listeners, 0, this, 0);
        if (MyWindow_instance.getSurf_lock()) {
            static_MyNBitTexture_f30(0, 0, "Entry Component", MyWindow_instance.colors.colorWhite);
            static_MyNBitTexture_f30(0, 32, "ESC.Quit", MyWindow_instance.colors.colorWhite);
            ProbablyConsole_instance.drawConsole();
            Pos2i* MousePos = MyWindow_instance.getMousePos();
            static_MyNBitTexture_f10(MousePos->x, MousePos->y, 8, MyWindow_instance.colors.colorRed);
            MyWindow_instance.getSurf_unlock();
            MyWindow_instance.prepareScreen();
            MyWindow_instance.surf_Blt();
        }
        if (isAppExitStatusSet())
            this->release();
    }
    return this->f4_nextComponent;
}

