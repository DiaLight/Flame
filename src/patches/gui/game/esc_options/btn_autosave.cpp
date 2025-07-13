//
// Created by DiaLight on 6/27/2025.
//
#include "btn_autosave.h"

#include <dk2/CDefaultPlayerInterface.h>
#include <dk2/button/button_types.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <filesystem>
#include <patches/logging.h>
#include <tools/flame_config.h>

namespace fs = std::filesystem;

bool patch::autosave::enabled = true;

flame_config::define_flame_option<int> o_autosave(
    "flame:autosave",
    "Autosave map in minutes\n"
    "0 - disable autosave\n"
    "",
    5
);

flame_config::define_flame_option<int> o_keepLastAutosavesSwitch(
    "flame:keep-last-autosaves",
    "Number of last autosaves to keep\n"
    "",
    3
);

namespace {

    void __cdecl CButton_handleLeftClick_AutosaveSwitch(int arg1, int arg2, dk2::CFrontEndComponent *front) {
        int autosave = *o_autosave;
        if (autosave < 0) autosave = 0;
        switch (arg1) {
            case 0: {
                if (autosave >= 5) {
                    autosave += 5;
                } else {
                    autosave++;
                }
                if (autosave >= 30) autosave = 30;
                o_autosave.set(autosave);
            } break;
            case 1: {
                if (autosave) {
                    int value = *o_keepLastAutosavesSwitch;
                    value++;
                    if (value >= 20) value = 20;
                    o_keepLastAutosavesSwitch.set(value);
                }
            } break;
        }
    }

    void __cdecl CButton_handleRightClick_AutosaveSwitch(int arg1, int arg2, dk2::CFrontEndComponent *front) {
        int autosave = *o_autosave;
        if (autosave < 0) autosave = 0;
        switch (arg1) {
            case 0: {
                if (autosave > 5) {
                    autosave -= 5;
                } else {
                    autosave--;
                }
                if (autosave < 0) autosave = 0;
                o_autosave.set(autosave);
            } break;
            case 1: {
                if (autosave) {
                    int value = *o_keepLastAutosavesSwitch;
                    value--;
                    if (value < 1) value = 1;
                    o_keepLastAutosavesSwitch.set(value);
                }
            } break;
        }
    }


    int __cdecl CClickButton_render_AutosaveSwitch(dk2::CButton *a1_btn, dk2::CDefaultPlayerInterface *a2_defplif) {
        int v14_try_level;

        dk2::AABB v13_tmp;
        dk2::Area4i pos = *(dk2::Area4i *) a2_defplif->cgui_manager.scaleAabb_2560_1920(&v13_tmp, (dk2::AABB *)&a1_btn->pos);

        dk2::PixelMask v11_pixelMask {0, 0, 0, 0, 0};
        if (a1_btn->f5D_isVisible != 1) return 0;

        unsigned __int8 v5_brightnes;
        if ( !a1_btn->f34_idxHigh || (v5_brightnes = -1, !a1_btn->f45_containsCursor) )
            v5_brightnes = -56;

        v11_pixelMask = {v5_brightnes, v5_brightnes, v5_brightnes, 0, 0};

        uint8_t *text = nullptr;
        int autosave = *o_autosave;
        if (autosave < 0) autosave = 0;
        switch (a1_btn->f63_clickHandler_arg1) {
            case 0: {

                static int autosaveTimeMinMb_value = -1;
                if (autosave != autosaveTimeMinMb_value) {
                    static uint8_t autosaveTimeMinMb[64];
                    wchar_t autosaveTimeMin[64];
                    if (autosave) {
                        wsprintfW(autosaveTimeMin, L"autosave in %d min", autosave);
                    } else {
                        wsprintfW(autosaveTimeMin, L"autosave disabled", autosave);
                    }
                    dk2::UniToMb_convert(autosaveTimeMin, autosaveTimeMinMb, sizeof(autosaveTimeMinMb));
                    text = autosaveTimeMinMb;
                }
            } break;
            case 1: {
                if (autosave) {
                    int value = *o_keepLastAutosavesSwitch;
                    if (value < 1) value = 1;

                    static int keepLastAutosavesMb_value = -1;
                    if (value != keepLastAutosavesMb_value) {
                        static uint8_t keepLastAutosavesMb[64];
                        wchar_t keepLastAutosaves[64];
                        wsprintfW(keepLastAutosaves, L"keep last %d autosaves", value);
                        dk2::UniToMb_convert(keepLastAutosaves, keepLastAutosavesMb, sizeof(keepLastAutosavesMb));
                        text = keepLastAutosavesMb;
                    }
                }
            } break;
        }
        if (text == nullptr) return 0;

        v14_try_level = -1;
        return a2_defplif->sub_42CB60(
            &a2_defplif->_options,
            pos.x, pos.y, text,
            &v11_pixelMask,
            0x11, 0, dk2::FontObj_3_instance, 1
        );
    }

    void doSilentAutosave() {
        char timeStr[80];
        {
            time_t rawtime;
            tm *timeinfo;
            time (&rawtime);
            timeinfo = localtime (&rawtime);
            strftime(timeStr,sizeof(timeStr),"%m%e-%H%M", timeinfo);
        }
        dk2::CDefaultPlayerInterface *defplif = &dk2::CDefaultPlayerInterface_instance;
        sprintf(defplif->saveFilePath, "%sautosave-%s.SAV", dk2::MyResources_instance.savesDir, timeStr);
        defplif->pCWorld->v_f28_saveToFile(defplif->saveFilePath);

        size_t keepLastAutosaves = *o_keepLastAutosavesSwitch;
        try {
            while (true) {
                fs::path oldestAutosave;
                fs::file_time_type oldestAutosaveTime;
                size_t autosaveCount = 0;
                for(const auto &p : fs::directory_iterator(dk2::MyResources_instance.savesDir, fs::directory_options::skip_permission_denied)) {
                    auto ext = p.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                    if(ext != ".sav") continue;
                    auto name = p.path().filename().string();
                    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                    if (!name.starts_with("autosave-")) continue;
                    autosaveCount++;
                    if (oldestAutosave.empty()) {
                        oldestAutosave = p.path();
                        oldestAutosaveTime = p.last_write_time();
                        continue;
                    }
                    auto lwt = p.last_write_time();
                    if (lwt < oldestAutosaveTime) {
                        oldestAutosave = p.path();
                        oldestAutosaveTime = lwt;
                    }
                }
                if (oldestAutosave.empty() || autosaveCount <= keepLastAutosaves) break;
                patch::log::dbg("remove autosave: %s", oldestAutosave.string().c_str());
                remove(oldestAutosave);
            }
        } catch (const std::exception &e) {
            patch::log::err("exc: %s", e.what());
        }

        dk2::DirFileList_instance1_saves_sav.reset();
        dk2::DirFileList_instance1_saves_sav.collectFiles(dk2::MyResources_instance.savesDir, "*.sav", 1);
    }

    uint32_t g_lastAutoSaveTime = 0;
    uint32_t g_enterMenuTime = 0;
    bool g_lastTickIsMenu = false;
}

void patch::autosave::Autosave_tick() {
    if (dk2::MyResources_instance.gameCfg.useFe_playMode == 3) return;  // multiplayer

    auto *profiler = &dk2::CGameComponent_instance.mt_profiler;
    dk2::CCamera *v2_camera = profiler->c_bridge->v_getCamera();
    int result = dk2::CCamera_mode_sub_44D870(v2_camera->_mode);
    if (result == 1) {
        // some camera state or multiplayer
        return;
    }
    dk2::CDefaultPlayerInterface *defplif = &dk2::CDefaultPlayerInterface_instance;
    if (defplif->pCWorld == NULL) return;

    if (profiler->inMenu) {
        if (!g_lastTickIsMenu) {
            g_enterMenuTime = dk2::getTimeMs();
            g_lastTickIsMenu = true;
        }
        return;
    }
    uint32_t curTime = dk2::getTimeMs();
    if (g_lastTickIsMenu) {
        g_lastTickIsMenu = false;
        // dont count menu time
        uint32_t timeToSkip = curTime - g_enterMenuTime;
        g_lastAutoSaveTime += timeToSkip;
    }

    uint32_t autosaveMinMs = *o_autosave * 60 * 1000;
    if (autosaveMinMs == 0) return;
    uint32_t timePassedMs = (curTime - g_lastAutoSaveTime);
    // patch::log::dbg("%d/%d", timePassedMs / 1000, autosaveMinMs / 1000);
    if (timePassedMs > autosaveMinMs) {
        doSilentAutosave();
    }
}

void patch::autosave::updateLastAutoSaveTime() {
    g_lastAutoSaveTime = dk2::getTimeMs();
}


dk2::ButtonCfg patch::autosave::Save_AutosaveSwitch_btn(dk2::Area4s a1, dk2::Area4s a2) {
    return {  // graphics options switch
        BT_CClickButton, 6, 0, CButton_handleLeftClick_AutosaveSwitch, CButton_handleRightClick_AutosaveSwitch, 0, 0, 0x00000000, 0x00000000, 0,
        a1.x, a1.y, (uint16_t) a1.w, (uint16_t) a1.h,
        (uint16_t) a2.x, (uint16_t) a2.y, (uint16_t) a2.w, (uint16_t) a2.h,
        0, NULL, CClickButton_render_AutosaveSwitch, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
}


dk2::ButtonCfg patch::autosave::Save_KeepLastAutosavesSwitch_btn(dk2::Area4s a1, dk2::Area4s a2) {
    return {  // graphics options switch
        BT_CClickButton, 6, 0, CButton_handleLeftClick_AutosaveSwitch, CButton_handleRightClick_AutosaveSwitch, 0, 0, 0x00000001, 0x00000000, 0,
        a1.x, a1.y, (uint16_t) a1.w, (uint16_t) a1.h,
        (uint16_t) a2.x, (uint16_t) a2.y, (uint16_t) a2.w, (uint16_t) a2.h,
        0, NULL, CClickButton_render_AutosaveSwitch, 0x00000000, 0, 0x00000000, 0x00000001, 21
    };
}
