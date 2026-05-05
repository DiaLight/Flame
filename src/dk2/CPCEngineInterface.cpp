//
// Created by DiaLight on 9/19/2025.
//
#include <dk2/CPCEngineInterface.h>
#include "dk2/SurfaceHolder.h"
#include "dk2/engine/game_engine.h"
#include "dk2_functions.h"
#include "dk2_globals.h"

int dk2::CPCEngineInterface::init3d() {
    __int16 v2_flags = MyResources_instance.video_settings.selected_3D_engine == 4;
    if (!MyWindow_instance.zbufferSurf) {
        v2_flags = 1;
        MyResources_instance.video_settings.setSelected3dEngine(4);
    }
    if (MyResources_instance.video_settings.untouched2_eq_1)
        v2_flags |= 2u;
    if (MyResources_instance.video_settings.cmd_flag_32BITTEXTURES)
        v2_flags |= 4u;
    if (MyResources_instance.video_settings.cmd_flag_SOFTWAREFILTER)
        v2_flags |= 8u;

    if (MyResources_instance.video_settings.isBumpmappingEnabled == 1) {
        v2_flags |= 0x10u;
    } else if (MyResources_instance.video_settings.isBumpmappingEnabled == 2) {
        v2_flags |= 0x20u;
    }

    int isLowResTexture = MyResources_instance.video_settings.high_res_texture == 0;
    MyDdSurfaceEx* primarySurf = &g_primarySurf; // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
    IDirectDrawSurface* ddPrimarySurf = MyDdSurface_addRef(&primarySurf->dd_surf, 0);
    IDirectDrawSurface* ddOffScreen = MyDdSurface_addRef(&MyWindow_instance.getCurOffScreenSurf()->dd_surf, 0);
    IDirectDraw* lpdd = ge_dk2dd_get(0);
    int initResult = MyDirectDraw_init(
        lpdd,
        ddOffScreen,
        ddPrimarySurf,
        &MyResources_instance.video_settings.deviceGuid,
        v2_flags,
        isLowResTexture);
    this->ddSceneInitResult = initResult;
    if (initResult) return 1;

    if ((v2_flags & 0x30) != 0) {
        v2_flags &= ~0x30u;
        int isLowResTexture_ = MyResources_instance.video_settings.high_res_texture == 0;
        MyDdSurfaceEx* primarySurf_ = &g_primarySurf; // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
        IDirectDrawSurface* lpddsurf = MyDdSurface_addRef(&primarySurf_->dd_surf, 0);
        MyDdSurfaceEx* offscrSurf_ = MyWindow_instance.getCurOffScreenSurf();
        IDirectDrawSurface* screenDdSurf_ = MyDdSurface_addRef(&offscrSurf_->dd_surf, 0);
        IDirectDraw* lpdd_ = ge_dk2dd_get(0);
        int initResult_ = MyDirectDraw_init(
            lpdd_,
            screenDdSurf_,
            lpddsurf,
            &MyResources_instance.video_settings.deviceGuid,
            v2_flags,
            isLowResTexture_);
        this->ddSceneInitResult = initResult_;
        if (initResult_)
            return 1;
    }
    MyResources_instance.video_settings.setSelected3dEngine(4);
    int isLowResTexture_1 = MyResources_instance.video_settings.high_res_texture == 0;
    MyDdSurfaceEx* primarySurf_1 = &g_primarySurf; // MyInputManagerCb_instance.inputSurf.v_getPrimarySurf(),  // 0079D200 &g_primarySurf
    IDirectDrawSurface* lpddsurf_1 = MyDdSurface_addRef(&primarySurf_1->dd_surf, 0);
    IDirectDrawSurface* screenDdSurf_1 = MyDdSurface_addRef(&MyWindow_instance.getCurOffScreenSurf()->dd_surf, 0);
    IDirectDraw* lpdd_1 = ge_dk2dd_get(0);
    int result = MyDirectDraw_init(
        lpdd_1,
        screenDdSurf_1,
        lpddsurf_1,
        &MyResources_instance.video_settings.deviceGuid,
        v2_flags | 1,
        isLowResTexture_1);
    this->ddSceneInitResult = result;
    return result;
}

int dk2::CPCEngineInterface::drawScene() {
    if ( this->smthEnabled || !this->ddSceneInitialized )
        return 0;
    bool v2 = this->sub_59AE10();
    if ( !engine_drawScene(v2) )
        this->doCallInit3d_2 = 1;
    if ( g_dbgDrawCircleAroundSceneObjects ) {
        static_MyWindow_swapSurfUnlock();
        ScreenObjectArr_static_renderItems();
    }
    this->ddSceneInitialized = 0;
    return 1;
}

