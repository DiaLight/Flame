//
// Created by DiaLight on 6/10/2025.
//
#include <dk2_functions.h>
#include <dk2_globals.h>
#include "dk2/dk2_memory.h"
#include "dk2/Rgba.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/entities/CObject.h"
#include "dk2/entities/data/MyObjectDataObj.h"
#include "dk2/gui/game/game_layout.h"


void dumpButtons(dk2::ButtonCfg *cur);
void dumpWindow(dk2::WindowCfg *cur);

int dk2::CDefaultPlayerInterface::fun_402D00(uint16_t a2_playerSceneId) {
    this->pCWorld = this->profiler->cworld;
    MyInputMethodEditor_instance2.restoreWndProc();
    this->playerTagId = a2_playerSceneId;
    this->f3B94 = 0;
    MyGame_instance.addWmActivateCallback((void (__cdecl *)(int, uint32_t, uint32_t, void *)) CDefaultPlayerInterface_WM_ACTIVATE_cb, this);
    this->field_133F_static_listeners.onKeyboardActionWithCtrl = (int (__cdecl *)(int, int, int, CComponent *)) CDefaultPlayerInterface_onKeyboardAction;
    this->field_133F_static_listeners.onMouseAction = (int (__cdecl *)(int, int, int, int, CComponent *)) CDefaultPlayerInterface_onMouseAction;
    this->field_133F_static_listeners.onWindowMsg = (int (__cdecl *)(__int16, WPARAM, LPARAM, CComponent *)) CDefaultPlayerInterface_onWindowMsg;
    this->f59_timestampMs = getTimeMs();
    this->commands.prev = ProbablyConsole_instance.setCommands(&this->commands);
    this->f1367 = 0;
    this->commands.initConsoleCommand("GUI", cmd_toggleGui, (CEntryComponent *) this);
    ProbablyConsole_instance.appendOutput("Default Player Interface attached");
    ProbablyConsole_instance.clear();

    // this->cgui_manager.createElements(gameView, this);
    this->cgui_manager.createElements(game_layout(), this);

    this->f12AE = 1;
    loadFontByScreenWidth(this->cgui_manager.width);
    this->sub_419180_loadSmth();
    this->sub_40AC40();
    this->renderInfo_F08.clear();
    DWORD *v3_surf = (DWORD *) dk2::operator_new(0xC000u);
    this->lpSurface = v3_surf;
    if (!v3_surf) return 0;

    CBridge *f10_c_bridge = this->profiler->c_bridge;
    g_isSomthingReady_006CE008 = 1;
    int v11_status[3];
    if (*MyDdSurface_createOffScreenSurface(v11_status, 0x100u, 0x100u, 0x800u, &my_surf.dd_surf) >= 0) {
        MyDblNamedSurface surfdn;
        surfdn.constructor("MapOverlay", "MapOver", 2, 0, 1);
        g_idx = MyEntryBuf_MyScaledSurface_create(&surfdn, 1);
        FSMAP_load_403060();
    }

    MyRenderInit_Sprite v12_init;
    v12_init.typeA = 3;
    v12_init.randRange = 0;
    v12_init.weB_flags = 0;

    int v10_idx;
    if (!f10_c_bridge->v_f54_allocateRenderObj("map_texture", 9, 0, &v10_idx, 1, 0)) return 0;

    this->worldEntry_map_texture.idx = v10_idx;
    this->worldEntry_map_texture._width.value = 4096;  // (f12) 1
    this->worldEntry_map_texture._height.value = 4096;  // (f12) 1
    this->worldEntry_map_texture.u = v12_init;
    this->worldEntry_map_texture.u.weB_flags |= this->worldEntry_map_texture.u.typeA != 0;

    Rgba *v6_rgbs = (Rgba *) dk2::operator_new(549 * sizeof(Rgba));
    if (!v6_rgbs) {
        this->_rgbs = NULL;
        return 0;
    }
    for (int i = 0; i < 549; ++i) {
        Rgba *v7_prgba = &v6_rgbs[i];
        v7_prgba->red = -1;
        v7_prgba->green = -1;
        v7_prgba->blue = -1;
        v7_prgba->alpha = -1;
    }
    this->_rgbs = v6_rgbs;
    this->sub_41E810();
    this->f4F2D = 0;

    if (!this->sub_42C7D0(
            MyGame_instance.dwWidth,
            (unsigned int) MyGame_instance.dwHeight >> 3,
            32, "FollowPathSubtitleTextBuffer", &this->_followPathSubtitleTextBuffer
    )) return 0;

    this->f410E = 0xFFFF;
    if (!this->obj507420.sub_5074D0(f10_c_bridge)) return 0;
    if (!this->sub_42BB30()) return 0;
    WeaNetR_instance.pChatCallback = (void (__cdecl *)(int, void *, void *)) CDefaultPlayerInterface_chatCallback;
    WeaNetR_instance.pChatCallback_owner = this;

    for (int i = 0; i < 7; ++i) {  // 0-6 = 0, 7 - dont touch for some reason
        g_enabledMessagesArr[i] = 0;
    }

    this->f3A = 0;
    this->f42 = 0;
    this->f3E = 0;
    this->f46 = 0;
    this->f4A = 0;
    this->f4E = 0;
    this->f46 = MySound_ptr->v_fun_567790("GLOBAL\\", "OPTIONS_MUSIC");
    this->f4A = MySound_ptr->v_fun_567790("GLOBAL\\", "OPTIONS_SPEECH");
    this->f4E = MySound_ptr->v_fun_567790("GLOBAL\\", "OBJECT_FE_PARCHMENT");
    this->v_fun_4033F0();
    return 1;
}

int dk2::CDefaultPlayerInterface::fun_4098D0() {
    if (!this->f12AE) {
        // this->cgui_manager.createElements(gameView, this);
        this->cgui_manager.createElements(game_layout(), this);
        this->sub_419180_loadSmth();
        this->cgui_manager.sub_52BC50(this);
        this->f12AE = 1;
    }
    if (this->hasThingsInHand(this->playerTagId)) {
        uint16_t v3_tagId = this->sub_40E050();
        CThing *v5_thing = (CThing *)sceneObjects[v3_tagId];

        int v4_idx = 7;
        if (v5_thing->fE_type == 2 && (((CObject *) v5_thing)->typeObj->flags & 0x40) != 0) {
            v4_idx = 9;
        }
        this->f12DA.nextIdx = v4_idx;
        this->f12DA.currentCursorIdx = v4_idx;
        this->f12DA.timeMs = getTimeMs();
        this->f12DA.dword_10 = 0;
    }
    this->_someTy = 0;
    return 1;
}

