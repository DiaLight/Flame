//
// Created by DiaLight on 24.07.2024.
//
#include "dk2/components/CGameComponent.h"

#include <patches/gui/game/esc_options/btn_autosave.h>
#include <patches/limit_tps.h>
#include <patches/logging.h>
#include <patches/scheduler.h>
#include <tools/flame_config.h>

#include "dk2/gui/CWindow.h"
#include "dk2/CCamera.h"
#include "dk2/MyDdSurfaceEx.h"
#include "dk2/utils/Bgraf.h"
#include "dk2/MyCollectDxAction_Action.h"
#include "dk2/CBridgeCmd.h"
#include "dk2/utils/Pos2i.h"
#include "dk2/text/render/MyTextRenderer.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "dk2/entities/CCreatureExtended.h"
#include "dk2/math/int_float.h"
#include "patches/micro_patches.h"
#include "patches/replace_mouse_dinput_to_user32.h"
#include "patches/protocol_dump.h"
#include "dk2/engine/game_engine.h"
#if __has_include(<dk2_research.h>)
#include "dk2_research.h"
#endif


dk2::CComponent *dk2::CGameComponent::mainGuiLoop() {
    patch::log::dbg("enter CGameComponent");
    GUID zero = {0};
    if (memcmp(&MyResources_instance.video_settings.deviceGuid, &zero, sizeof(GUID)) == 0) {
        MyD3DevInfo devInfo_;
        if (MyWindow_instance.sub_558F40(2u, &devInfo_)) {
            MyResources_instance.video_settings.selectDevice(&devInfo_);
        }
    }

    int hardware3d = 1;
    if (!MyWindow_prepareWithSettings(&hardware3d)) return NULL;
    if (MyResources_instance.gameCfg.useFe3d && !CFrontEndComponent_instance.launchGame()) return NULL;
    Pos2i v29 {0, 0};
    int status;
    static_MyInputManagerCb_setCursorIconAndDraw(&status, NULL, NULL, &v29);
    CWorld_instance.showLoadingScreen();
    CWorld_instance.releaseLoadingScreenSurface();
    CWorld_instance.fun_511250();
    if (!MyResources_instance.gameCfg.useFe2d_unk1)
        this->gameSession.init();
    CCommunicationInterface* v2_comm_i;
    v2_comm_i = &CNetworkCommunication_instance;
    if (MyResources_instance.gameCfg.useFe_playMode != 3)
        v2_comm_i = &CLocalCommunication_instance;
//    CCommunicationInterface *v32;
//    v32 = v2_comm_i;  // probably seh
    resetSceneObjectCount();
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        if (!CBridge_instance.connectEngine(&CPCEngineInterface_instance_start))
            return NULL;
        if (!MyResources_instance.gameCfg.useFe2d_unk1) {
            if (!this->gameSession.attachCommunicationInterface(v2_comm_i))
                return NULL;
            if (!this->gameSession.attachCBridge(&CBridge_instance, &MyResources_instance.video_settings)) {
                if (hardware3d) {
                    hardware3d = 0;
                    MyResources_instance.video_settings.setSelected3dEngine(4);
                    if (!MyWindow_prepareWithSettings(&hardware3d))
                        return NULL;
                    if (!this->gameSession.attachCBridge(&CBridge_instance, &MyResources_instance.video_settings))
                        return NULL;
                }
            }
        }
    }
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        if (MyResources_instance.gameCfg.useFe3d) {
            CFrontEndComponent_instance.sub_535950(this->gameSession.pBridge);
        }
        if (!MyResources_instance.gameCfg.useFe2d_unk1) {
            if (!this->gameSession.attachCWorld(&CWorld_instance))
                return NULL;
        }
    }

    if (MyResources_instance.gameCfg.hasSaveFile) {
        if (patch::buffer_overrun_fix::enabled) {
            char* SavFile = MyResources_instance.gameCfg.getSavFile();
            wchar_t Buffer[MAX_PATH];
            swprintf(Buffer, L"%s", SavFile);
            CHAR MultiByteStr[MAX_PATH];
            unicodeToUtf8(Buffer, MultiByteStr, MAX_PATH);
            char v41[MAX_PATH];
            _sprintf(v41, "%s%s", MyResources_instance.savesDir, MultiByteStr);
            CWorld_instance.showLoadingScreen();
            CWorld_instance.releaseLoadingScreenSurface();
            CWorld_instance.initUpdateProgressFun();
            int v4 = CWorld_instance._loadSaveFile((int) v41);
            CWorld_instance.fun_5111E0();
            if (!v4)
                return NULL;
        } else {
            char* SavFile = MyResources_instance.gameCfg.getSavFile();
            wchar_t Buffer[64];
            swprintf(Buffer, L"%s", SavFile);
            CHAR MultiByteStr[64];
            unicodeToUtf8(Buffer, MultiByteStr, 64);
            char v41[64];
            _sprintf(v41, "%s%s", MyResources_instance.savesDir, MultiByteStr);
            CWorld_instance.showLoadingScreen();
            CWorld_instance.releaseLoadingScreenSurface();
            CWorld_instance.initUpdateProgressFun();
            int v4 = CWorld_instance._loadSaveFile((int) v41);
            CWorld_instance.fun_5111E0();
            if (!v4)
                return NULL;
        }
    } else if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        CHAR MultiByteStr[64];
        if (!unicodeToUtf8(MyResources_instance.gameCfg.levelName, MultiByteStr, 64))
            return NULL;
        CWorld_instance.showLoadingScreen();
        CWorld_instance.releaseLoadingScreenSurface();
        CWorld_instance.initUpdateProgressFun();
        if (!CWorld_instance.loadLevel(MultiByteStr)) {
            CWorld_instance.fun_5111E0();
            CWorld_instance.releaseLoadingScreenSurface();
            sprintf(g_temp_string, "Unable to load level, %s", MultiByteStr);
            return NULL;
        }
        CWorld_instance.fun_5111E0();
    }
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        CWorld* cworld = this->gameSession.pWorld;
        int playerTagId = cworld->v_getMEPlayerTagId();
        if (!MyResources_instance.gameCfg.useFe3d) {
            int v8 = this->gameSession.pWorld->v_getMEPlayerTagId();
            if (!this->gameSession.attachPlayerI(&CDefaultPlayerInterface_instance, v8))
                return 0;
            this->gameSession.pPlayer->playerTagId = playerTagId;
        }
        if (CPCEngineInterface_instance_start.pCBridge) {
            CBridge* cBridge = CPCEngineInterface_instance_start.pCBridge;
            cBridge->v_fC0_setPlayerId(playerTagId);
            cBridge->v_fC8_setNeutralPlayerId(g_neutralPlayerId);
        }
        CWorld_instance.showLoadingScreen();
        CWorld_instance.releaseLoadingScreenSurface();
        CBridgeCmd a2;
        a2.a1 = 1;
        a2.a2 = 0;
        a2.a3 = 0;
        a2.cmd = 7;

//        int v43;
//        v43 = 0;  // seh try level
        cworld->execCBridgeCmd(&a2);
//        v2_comm_i = v30;  // probably seh
//        v43 = -1;  // seh try level
    }
    CWorld_instance.showLoadingScreen();
    CWorld_instance.releaseLoadingScreenSurface();
    if (!CWorld_instance.sub_511280())
        this->exit_flag = 1;
    v2_comm_i->sub_521B80();
    this->fpsCalc_drawCount = 0;
    this->fps.value = 0;
    this->fpsCalc_lastTimeMs = getTimeMs();
    if (MyResources_instance.gameCfg.useFe3d) {
        static_CFrontEndComponent_sub_536F90(0);
        CFrontEndComponent_instance.fun_536E20(1, 0);
        CFrontEndComponent_instance.fun_537290();
        CFrontEndComponent_instance.fun_537980();
    }
    CurOffScreen_clearWithPalette0(Bgraf{
        g_paletteEntries[0].peBlue,
        g_paletteEntries[0].peGreen,
        g_paletteEntries[0].peRed,
        0xFF, 0});
    CurOffScreen_clearWithPalette0(Bgraf{
        g_paletteEntries[0].peBlue,
        g_paletteEntries[0].peGreen,
        g_paletteEntries[0].peRed,
        0xFF, 0});
    patch::autosave::updateLastAutoSaveTime();
    // hook::BEFORE_GAME_LOOP
    while (!this->exit_flag) {
        // hook::TICK_GAME_LOOP
#if __has_include(<dk2_research.h>)
        research::tick();
#endif
        patch::scheduler::tick();
        if (flame_config::changed())
            flame_config::save();
        patch::protocol_dump::tick();
        patch::replace_mouse_dinput_to_user32::release_handled_dinput_actions();
        if (!MyWindow_instance.isNeedBlt()) {
            MyCollectDxAction_Action dxAct;
            while (MyInputManagerCb_static_popDxAction(&dxAct)) {
                if (dxAct.type == 2)
                    this->exit_flag = 1;
            }
            process_win_inputs();
            if (this->exit_flag)
                break;
        }
        int needBlt = MyWindow_instance.isNeedBlt();
        if (isAppExitStatusSet())
            this->exit_flag = 1;
        if (MyResources_instance.gameCfg.useFe3d) {
            BOOL v12 = CFrontEndComponent_instance.cgui_manager.sub_52C520();
            MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                &CFrontEndComponent_instance.static_listeners,
                !v12,
                &CFrontEndComponent_instance,
                0);
            CFrontEndComponent_instance.cgui_manager.sub_52BC50(
                (CDefaultPlayerInterface*) &CFrontEndComponent_instance);
            CWindow* curWindow = CFrontEndComponent_instance.getCurrentWindow();
            if (curWindow) {
                if (curWindow->f24_getPanelItemsCount)
                    curWindow->f24_getPanelItemsCount(curWindow, 0, &CFrontEndComponent_instance);
            }
            CFrontEndComponent_tickMainGui(&CFrontEndComponent_instance);
            if (CFrontEndComponent_instance.is_component_destroy)
                this->exit_flag = 1;
        }
        if (!MyResources_instance.gameCfg.useFe2d_unk1 && !this->gameSession.tick(needBlt))
            this->exit_flag = 1;
        if (needBlt && (this->gameSession.f268 || MyResources_instance.gameCfg.f12C)) {
            MyWindow_instance.takeScreenshot();
            this->gameSession.f268 = 0;
        }
        if (MyResources_instance.gameCfg.useFe3d) {
            if (CFrontEndComponent_instance.key_DIK_SYSRQ) {
                MyWindow_instance.takeScreenshot();
                CFrontEndComponent_instance.key_DIK_SYSRQ = 0;
            }
            if (MyResources_instance.gameCfg.useFe3d)
                CFrontEndComponent_instance.draw2dGui();
        }
        if (needBlt) {
            MyWindow_instance.prepareScreen();
            if (MyResources_instance.video_settings.selected_3D_engine != 4)
                MyWindow_instance.surf_Blt();
        }
        patch::autosave::Autosave_tick();
        ++this->fpsCalc_drawCount;
        patch::limit_tps::call();
        // calc fps
        DWORD deltaTimeMs = getTimeMs() - this->fpsCalc_lastTimeMs;
        if (deltaTimeMs > 1000) {
            // inf as float with 12 bit precision math
            // fps = (1000 * drawCount) / deltaTime
            IntFloat12 deltaTimeMsFl = dk2ex::IFl12_from(deltaTimeMs);
            // tryLevel = 2
            IntFloat12 num = dk2ex::IFl12_from(1000 * this->fpsCalc_drawCount);
            IntFloat12 buf;
            IntFloat12* fpsResult = num.div(&buf, &deltaTimeMsFl);
            // tryLevel = -1
            this->fps = *fpsResult;
            this->fpsCalc_lastTimeMs = getTimeMs();
            this->fpsCalc_drawCount = 0;
//            patch::log::dbg("tps: %.2f", dk2ex::toFloat(this->fps));
        }
    }
    // hook::AFTER_GAME_LOOP
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        CCamera* pCamera = this->gameSession.pBridge->v_fD0_getCamera();
        Vec3i pos;
        pos.x = 0;
        pos.y = 0;
        pos.z = 0;
        pCamera->fun_449AC0(&pos);
        pCamera->updateCameraMode(3, 0);
    }
    if (!MyResources_instance.gameCfg.useFe3d)
        this->gameSession.detachPlayerI(&CDefaultPlayerInterface_instance);
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        this->gameSession.clearCommunicationInterface((int) v2_comm_i);
        this->gameSession.clearCWorld(&CWorld_instance);
        this->gameSession.clearCBridge(&CBridge_instance);
        CBridge_instance.fun_43ACF0();
        this->gameSession.dumpStats();
    }
    TbWickedSpriteBank_sub_5B2D80(&this->wicked_sprite_bank);
    int useFe3d = MyResources_instance.gameCfg.useFe3d;
    if (MyResources_instance.gameCfg.useFe3d) {
        CFrontEndComponent_instance.fun_52F550();
        useFe3d = MyResources_instance.gameCfg.useFe3d;
        MyResources_instance.gameCfg.useFe2d_unk1 = 0;
    }
    if (MyResources_instance.gameCfg.useFe_playMode == 3 && !useFe3d) {
        Pos2i pos;
        pos.x = 0;
        pos.y = 0;
        MyInputManagerCb_static_setMousePos(&pos);
        MyDdSurfaceEx_fillWithColor(
            &status, MyWindow_instance.getCurOffScreenSurf(), NULL,
            Bgraf{0, 0, 0, 0xFF, 0}, 0);
        MyDdSurfaceEx_fillWithColor(
            &status,
            &g_primarySurf, // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
            NULL,
            Bgraf{0, 0, 0, 0xFF, 0}, 0);
        Sleep(50);
        AABB aabb;
        aabb.maxY = MyWindow_instance.dwHeight;
        aabb.minX = 0;
        aabb.minY = 0;
        aabb.maxX = MyWindow_instance.dwWidth;
        if (MyWindow_instance.selectSurfToRender()) {
            if (CWorld_instance.fA3C3) {
                uint8_t __buf[sizeof(MyTextRenderer)];
                MyTextRenderer& v40 = *(MyTextRenderer*) &__buf;
                v40.constructor();
                v40.selectMyCR(&status, 2);
                v40.selectMyTR(&status, 2);
                uint8_t* MbString = MyMbStringList_idx1091_getMbString(CWorld_instance.fA3C3);
                Bgraf color{0xFF, 0xFF, 0xFF, 0xFF, 0};
                g_FontObj5_instance.setColor(&status, &color);
                v40.renderText(
                    &status,
                    &aabb,
                    MbString,
                    &g_FontObj5_instance,
                    NULL);
                v40.destructor();
            }
            MyWindow_instance.getSurf_unlock();
            MyWindow_instance.prepareScreen();
            Sleep(5000);
        }
        useFe3d = MyResources_instance.gameCfg.useFe3d;
    }
    if (MyResources_instance.gameCfg.f200)
        return NULL;
    if (useFe3d && MyResources_instance.gameCfg.unk_f16C) {
        CComponent* result = CFrontEndComponent_instance.f4_nextComponent;
        MyResources_instance.gameCfg.useFe3d = 0;
        return result;
    }
    if (useFe3d)
        return NULL;
    if (MyResources_instance.gameCfg.unk_f16C) {
        MyResources_instance.gameCfg.useFe3d = 1;
        MyResources_instance.gameCfg.useFe_unk3 = MyResources_instance.gameCfg.useFe_playMode;
        MyResources_instance.gameCfg.useFe_playMode = 5;
        wcsncpy(MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64u);
        MyResources_instance.gameCfg.levelName[63] = 0;
        MyResources_instance.gameCfg.hasSaveFile = 0;
        MyResources_instance.gameCfg.useFe_unkTy = 3;
        return &CGameComponent_instance;
    }
    if (g_value2 != 101) return NULL;
    return (CGameComponent*) &CFrontEndComponent_instance;
}

