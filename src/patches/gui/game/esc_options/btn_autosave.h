//
// Created by DiaLight on 6/27/2025.
//

#ifndef BTN_AUTOSAVE_H
#define BTN_AUTOSAVE_H


#include <dk2/CWorld.h>
#include <dk2/button/CButton.h>
#include <dk2/utils/Area4s.h>

namespace patch::autosave {

    extern bool enabled;

    void Autosave_tick();
    void updateLastAutoSaveTime();
    dk2::ButtonCfg Save_AutosaveSwitch_btn(dk2::Area4s a1, dk2::Area4s a2);
    dk2::ButtonCfg Save_KeepLastAutosavesSwitch_btn(dk2::Area4s a1, dk2::Area4s a2);

}

#endif //BTN_AUTOSAVE_H
