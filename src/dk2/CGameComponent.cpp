//
// Created by DiaLight on 24.07.2024.
//
#include "dk2/CGameComponent.h"
#include "dk2/CWindow.h"
#include "dk2/CCamera.h"
#include "dk2/MyDdSurfaceEx.h"
#include "dk2/Bgra.h"
#include "dk2/MyCollectDxAction_Action.h"
#include "dk2/CBridgeCmd.h"
#include "dk2/utils/Pos2i.h"
#include "dk2/text/render/MyTextRenderer.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"
#include "patches/replace_mouse_dinput_to_user32.h"


dk2::CGameComponent *dk2::CGameComponent::mainGuiLoop() {
    _GUID zero = {0};
    if(memcmp(&MyResources_instance.video_settings.deviceGuid, &zero, sizeof(_GUID)) == 0) {
        MyD3DevInfo devInfo_;
        if (MyGame_instance.sub_558F40(2u, &devInfo_)) {
            MyResources_instance.video_settings.selectDevice(&devInfo_);
        }
    }

    int v31 = 1;
    if ( !MyGame_prepareWithSettings(&v31)) return 0;
    if (MyResources_instance.gameCfg.useFe3d && !CFrontEndComponent_instance.launchGame() ) return 0;
    Pos2i v29;
    v29.x = 0;
    v29.y = 0;
    int status;
    static_MyInputManagerCb_sub_5B2BD0(&status, 0, 0, &v29);
    CWorld_instance.showLoadingScreen();
    CWorld_instance.releaseSurface();
    CWorld_instance.fun_511250();
    if (!MyResources_instance.gameCfg.useFe2d_unk1) this->mt_profiler.constructor2();
    CCommunicationInterface *v2_comm_i;
    v2_comm_i = &CNetworkCommunication_instance;
    if ( MyResources_instance.gameCfg.useFe_playMode != 3 )
        v2_comm_i = &CLocalCommunication_instance;
//    CCommunicationInterface *v32;
//    v32 = v2_comm_i;  // probably seh
    resetSceneObjectCount();
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        if (!CBridge_instance.connectEngine(&CPCEngineInterface_instance_start)) return 0;
        if (!MyResources_instance.gameCfg.useFe2d_unk1) {
            if (!this->mt_profiler.attachCommunicationInterface(v2_comm_i)) return 0;
            if (!this->mt_profiler.attachCBridge(&CBridge_instance, &MyResources_instance.video_settings)) {
                if ( v31 ) {
                    v31 = 0;
                    MyResources_instance.video_settings.setSelected3dEngine(4);
                    if (!MyGame_prepareWithSettings(&v31)) return 0;
                    if (!this->mt_profiler.attachCBridge(&CBridge_instance, &MyResources_instance.video_settings)) return 0;
                }
            }
        }
    }
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        if ( MyResources_instance.gameCfg.useFe3d) {
            CFrontEndComponent_instance.sub_535950(this->mt_profiler.c_bridge);
        }
        if (!MyResources_instance.gameCfg.useFe2d_unk1) {
            if(!this->mt_profiler.attachCWorld(&CWorld_instance)) return 0;
        }
    }

    if (MyResources_instance.gameCfg.hasSaveFile) {
        char *SavFile = MyResources_instance.gameCfg.getSavFile();
        wchar_t Buffer[64];
        swprintf(Buffer, L"%s", SavFile);
        CHAR MultiByteStr[64];
        unicodeToUtf8(Buffer, MultiByteStr, 64);
        char v41[64];
        _sprintf(v41, "%s%s", MyResources_instance.savesDir, MultiByteStr);
        CWorld_instance.showLoadingScreen();
        CWorld_instance.releaseSurface();
        CWorld_instance.fun_511180();
        int v4 = CWorld_instance.fun_50E920((int)v41);
        CWorld_instance.fun_5111E0();
        if ( !v4 ) return 0;
    } else if(!MyResources_instance.gameCfg.useFe2d_unk1) {
        CHAR MultiByteStr[64];
        if(!unicodeToUtf8(MyResources_instance.gameCfg.levelName, MultiByteStr, 64)) return 0;
        CWorld_instance.showLoadingScreen();
        CWorld_instance.releaseSurface();
        CWorld_instance.fun_511180();
        if(!CWorld_instance.loadLevel(MultiByteStr)) {
            CWorld_instance.fun_5111E0();
            CWorld_instance.releaseSurface();
            sprintf(temp_string, "Unable to load level, %s", MultiByteStr);
            return 0;
        }
        CWorld_instance.fun_5111E0();
    }
    if (!MyResources_instance.gameCfg.useFe2d_unk1) {
        CWorld *cworld = this->mt_profiler.cworld;
        int playerTagId = cworld->v_getMEPlayerTagId();
        if ( !MyResources_instance.gameCfg.useFe3d ) {
            int v8 = this->mt_profiler.cworld->v_getMEPlayerTagId();
            if ( !this->mt_profiler.attachPlayerI(&CDefaultPlayerInterface_instance, v8) )
                return 0;
            this->mt_profiler.player_i->_cpyToF10 = playerTagId;
        }
        if(CPCEngineInterface_instance_start.pCBridge) {
            CBridge *cBridge = CPCEngineInterface_instance_start.pCBridge;
            cBridge->v_fC0(playerTagId);
            cBridge->v_fC8(g_neutralPlayerId);
        }
        CWorld_instance.showLoadingScreen();
        CWorld_instance.releaseSurface();
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
    CWorld_instance.releaseSurface();
    if ( !CWorld_instance.sub_511280() )
        this->exit_flag = 1;
    v2_comm_i->sub_521B80();
    this->drawCount = 0;
    this->fps.value = 0;
    this->lastTimeMs = getTimeMs();
    if (MyResources_instance.gameCfg.useFe3d) {
        static_CFrontEndComponent_sub_536F90(0);
        CFrontEndComponent_instance.fun_536E20(1, 0);
        CFrontEndComponent_instance.fun_537290();
        CFrontEndComponent_instance.fun_537980();
    }
    Bgra v22;
    Bgra *v27 = &v22;
    v22.red = palleteEntries[0].peRed;
    v22.green = palleteEntries[0].peGreen;
    v22.blue = palleteEntries[0].peBlue;
    v22.alpha = -1;
    initCurOffScreenSurf(v22, 0);
    Bgra v23;
    Bgra *v28 = &v23;
    v23.red = palleteEntries[0].peRed;
    v23.green = palleteEntries[0].peGreen;
    v23.blue = palleteEntries[0].peBlue;
    v23.alpha = -1;
    initCurOffScreenSurf(v23, 0);
    // hook::BEFORE_GAME_LOOP
    while ( !this->exit_flag ) {
        // hook::TICK_GAME_LOOP
        if(control_windowed_mode::enabled) limit_fps::call();
        replace_mouse_dinput_to_user32::release_handled_dinput_actions();
        if ( !MyGame_instance.isNeedBlt() ) {
            MyCollectDxAction_Action dxAct;
            while ( MyInputManagerCb_static_popDxAction(&dxAct) ) {
                if ( dxAct.type == 2 )
                    this->exit_flag = 1;
            }
            process_win_inputs();
            if ( this->exit_flag )
                break;
        }
        int needBlt = MyGame_instance.isNeedBlt();
        if ( isAppExitStatusSet() )
            this->exit_flag = 1;
        if ( MyResources_instance.gameCfg.useFe3d ) {
            BOOL v12 = CFrontEndComponent_instance.cgui_manager.sub_52C520();
            MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(
                    &CFrontEndComponent_instance.static_listeners,
                    !v12,
                    &CFrontEndComponent_instance,
                    0);
            CFrontEndComponent_instance.cgui_manager.sub_52BC50(
                    (CDefaultPlayerInterface *)&CFrontEndComponent_instance);
            CWindow *CurrentWindow = CFrontEndComponent_instance.getCurrentWindow();
            if ( CurrentWindow ) {
                void (__cdecl *f24_fun)(CWindow *, uint32_t, CFrontEndComponent *); // ecx
                f24_fun = CurrentWindow->f24_fun;
                if ( f24_fun )
                    f24_fun(CurrentWindow, 0, &CFrontEndComponent_instance);
            }
            CFrontEndComponent_do_special_gui(&CFrontEndComponent_instance);
            if ( CFrontEndComponent_instance.is_component_destroy )
                this->exit_flag = 1;
        }
        if ( !MyResources_instance.gameCfg.useFe2d_unk1 && !this->mt_profiler.draw3dScene(needBlt) )
            this->exit_flag = 1;
        if ( needBlt && (this->mt_profiler.f268 || MyResources_instance.gameCfg.f12C) ) {
            MyGame_instance.takeScreenshot();
            this->mt_profiler.f268 = 0;
        }
        if ( MyResources_instance.gameCfg.useFe3d ) {
            if ( CFrontEndComponent_instance.key_DIK_SYSRQ ) {
                MyGame_instance.takeScreenshot();
                CFrontEndComponent_instance.key_DIK_SYSRQ = 0;
            }
            if ( MyResources_instance.gameCfg.useFe3d )
                CFrontEndComponent_instance.draw2dGui();
        }
        if ( needBlt ) {
            MyGame_instance.prepareScreen();
            if ( MyResources_instance.video_settings.selected_3D_engine != 4 ) MyGame_instance.surf_Blt();
        }
        ++this->drawCount;
        DWORD deltaTime = getTimeMs() - this->lastTimeMs;
        if (deltaTime > 1000 ) {
            // inf as float with 12 bit precision math
            // fps = (1000 * this->drawCount) / deltaTime
            int v35 = deltaTime << 12;
            IntFloat12 num = { (1000 * this->drawCount) << 12 };
            uint32_t out;
            this->fps.value = *num.shl12_div(&out, &v35);
            this->lastTimeMs = getTimeMs();
            this->drawCount = 0;
        }
    }
    // hook::AFTER_GAME_LOOP
    if ( !MyResources_instance.gameCfg.useFe2d_unk1 ) {
        CCamera *v16_camera = this->mt_profiler.c_bridge->v_getCamera();
        Vec3i pos;
        pos.x = 0;
        pos.y = 0;
        pos.z = 0;
        v16_camera->fun_449AC0(&pos);
        v16_camera->updateCameraMode(3, 0);
    }
    if ( !MyResources_instance.gameCfg.useFe3d )
        this->mt_profiler.detach(&CDefaultPlayerInterface_instance);
    if ( !MyResources_instance.gameCfg.useFe2d_unk1 ) {
        this->mt_profiler.clearCommunicationInterface((int) v2_comm_i);
        this->mt_profiler.clearCWorld(&CWorld_instance);
        this->mt_profiler.clearCBridge(&CBridge_instance);
        CBridge_instance.fun_43ACF0();
        this->mt_profiler.dumpStats();
    }
    TbWickedSpriteBank_sub_5B2D80(&this->wicked_sprite_bank);
    int useFe3d = MyResources_instance.gameCfg.useFe3d;
    if ( MyResources_instance.gameCfg.useFe3d ) {
        CFrontEndComponent_instance.fun_52F550();
        useFe3d = MyResources_instance.gameCfg.useFe3d;
        MyResources_instance.gameCfg.useFe2d_unk1 = 0;
    }
    if ( MyResources_instance.gameCfg.useFe_playMode == 3 && !useFe3d ) {
        Pos2i pos;
        pos.x = 0;
        pos.y = 0;
        MyInputManagerCb_static_setMousePos(&pos);
        MyDdSurfaceEx *CurOffScreenSurf = MyGame_instance.getCurOffScreenSurf();
        __surface_init_blt(&status, CurOffScreenSurf, 0, 0xFF000000, 0, 0);
        MyDdSurfaceEx *PrimarySurf = MyGame_instance.getPrimarySurf();
        __surface_init_blt(&status, PrimarySurf, 0, 0xFF000000, 0, 0);
        Sleep(0x32u);
        AABB aabb;
        aabb.maxY = MyGame_instance.dwHeight;
        aabb.minX = 0;
        aabb.minY = 0;
        aabb.maxX = MyGame_instance.dwWidth;
        if (MyGame_instance.selectSurfToRender()) {
            if ( CWorld_instance.fA3C3 ) {
                uint8_t __buf[sizeof(MyTextRenderer)];
                MyTextRenderer &v40 = *(MyTextRenderer *) &__buf;
                v40.constructor();
                v40.selectMyCR(&status, 2);
                v40.selectMyTR(&status, 2);
                uint8_t *MbString = MyMbStringList_idx1091_getMbString(CWorld_instance.fA3C3);
                PixelMask mask;
                mask.f0 = 0xFF;
                mask.f1 = 0xFF;
                mask.f2 = 0xFF;
                mask.f3 = 0xFF;
                mask.f4 = 0;
                g_FontObj5_instance.setFontMask(&status, &mask);
                v40.renderText(
                        &status,
                        &aabb,
                        MbString,
                        &g_FontObj5_instance,
                        0);
                v40.destructor();
            }
            MyGame_instance.getSurf_unlock();
            MyGame_instance.prepareScreen();
            Sleep(0x1388u);
        }
        useFe3d = MyResources_instance.gameCfg.useFe3d;
    }
    if ( MyResources_instance.gameCfg.f200 ) return 0;
    if ( useFe3d && MyResources_instance.gameCfg.unk_f16C ) {
        CGameComponent *result = (CGameComponent *)CFrontEndComponent_instance.field_4;
        MyResources_instance.gameCfg.useFe3d = 0;
        return result;
    }
    if ( useFe3d ) return 0;
    if ( MyResources_instance.gameCfg.unk_f16C ) {
        MyResources_instance.gameCfg.useFe3d = 1;
        MyResources_instance.gameCfg.useFe_unk3 = MyResources_instance.gameCfg.useFe_playMode;
        MyResources_instance.gameCfg.useFe_playMode = 5;
        wcsncpy(MyResources_instance.gameCfg.levelName, L"FrontEnd3DLevel", 64u);
        MyResources_instance.gameCfg.levelName[63] = 0;
        MyResources_instance.gameCfg.hasSaveFile = 0;
        MyResources_instance.gameCfg.useFe_unkTy = 3;
        return &CGameComponent_instance;
    }
    if ( g_value2 != 101 ) return 0;
    return (CGameComponent *)&CFrontEndComponent_instance;
}

