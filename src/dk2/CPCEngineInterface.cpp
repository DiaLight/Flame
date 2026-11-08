//
// Created by DiaLight on 9/19/2025.
//
#include <dk2/CPCEngineInterface.h>
#include "dk2/engine/game_engine.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "dk2/engine/scene/MyDirectDraw_engine.h"
#include "dk2/utils/Vec3d.h"
#include "dk2/math/vec.h"
#include "dk2/math/mat.h"
#include "dk2/math/q12_utils.h"
#include "dk2/utils/Vec3q12.h"
#include "dk2/MyDLVec2i.h"
#include "dk2/MyLVec3f.h"
#include <cmath>
#include <exception>

int dk2::CPCEngineInterface::init3d() {
    __int16 v2_flags = MyResources_instance.video_settings.selected_3D_engine == EngineType_Software3D_MMX;
    if (!MyWindow_instance.zbufferSurf) {
        v2_flags = 1;
        MyResources_instance.video_settings.setSelected3dEngine(EngineType_Software3D_MMX);
    }
    if (MyResources_instance.video_settings.untouched2_eq_1)
        v2_flags |= MyDirectDraw_useGammaRamps;
    if (MyResources_instance.video_settings.cmd_flag_32BITTEXTURES)
        v2_flags |= MyDirectDraw_32BITTEXTURES;
    if (MyResources_instance.video_settings.cmd_flag_SOFTWAREFILTER)
        v2_flags |= MyDirectDraw_SOFTWAREFILTER;

    if (MyResources_instance.video_settings.bumpMappingConfig == 1) {
        v2_flags |= MyDirectDraw_isBumpmappingSimpleEnabled;
    } else if (MyResources_instance.video_settings.bumpMappingConfig == 2) {
        v2_flags |= MyDirectDraw_isBumpmappingLuminanceEnabled;
    }

    if(patch::opengl_patch::enabled) {
        v2_flags &= ~MyDirectDraw_isSoftware3D_MMX;  // dont use software engine
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

int dk2::CPCEngineInterface::updateCameraState(UpdateCameraStateArgs *args) {
    CPCEngineInterface *this_ = this;
    setShadowLevel(MyResources_instance.video_settings.shadow_level);
    this->animInterpolationFactorC1 = (double) ((getTimeMs() >> 2) % 1000) * 0.001;
    engine_setRenderArea(0, 0, MyWindow_instance.dwWidth, MyWindow_instance.dwHeight);
    this->gameTick = args->gameTick278_last;
    this->tickPercent256 = args->tickPercent256;

    MyCameraState state;
    state.v3f = Vec3f {0, 0, 0};
    state.viewMat.reset(1);
    state.ww240_viewRange = 0;
    state.leftRight = Vec2f{0, 0};
    state.topBottom = Vec2f{0, 0};
    state.trg = Vec2f{0, 0};
    state.farPlane = 0.0;
    state.flags = state.flags & ~0xF | 4;

    CCamera *cam = this->pCBridge->v_fD0_getCamera();
    state.leftRight.x = (float) cam->aabbE62_clipSpace.minX;
    state.leftRight.y = (float) cam->aabbE62_clipSpace.maxX;
    state.topBottom.x = (float) cam->aabbE62_clipSpace.minY;
    state.topBottom.y = (float) cam->aabbE62_clipSpace.maxY;

    if (cam->_mode == 7) {  // map mode
        unsigned int gwidth = MyWindow_instance.dwWidth;
        unsigned int gheight = MyWindow_instance.dwHeight;
        Pos2i *mousePos = MyWindow_instance.getMousePos();
        CWorld *pWorld = this->f0_pGameSession->pWorld;

        float cMapHeight = (float) pWorld->v_getCMapHeight_508FB0();
        float cMapWidth = (float) pWorld->v_getCMapWidth_508FA0();

        int width41 = 41 * g_cgui_manager_width_6CE590 / 640;
        int height33 = 33 * g_cgui_manager_height_6CD190 / 480;
        int width425 = 425 * g_cgui_manager_width_6CE590 / 640 - width41;
        int height417 = 417 * g_cgui_manager_height_6CD190 / 480 - height33;

        int cMapWidthi = (__int64) cMapWidth;
        int cMapHeighti = (__int64) cMapHeight;
        adjust_size_to_aspect_ratio(&cMapWidthi, &cMapHeighti, width425, height417);

        double centerX = height33 + (height417 - (__int64) cMapHeight) / 2;
        double centerY = width41 + (width425 - (__int64) cMapWidth) / 2;
        double mouseOffsX = (float) mousePos->y - (double) centerX;
        double mouseOffsY = (float) mousePos->x - (double) centerY;

        state.v3f = Vec3f {
                (float) (mouseOffsY * cMapWidth / (double) (__int64) cMapWidth),
                (float) (mouseOffsX * cMapHeight / (double) (__int64) cMapHeight),
                -8.f,
        };
        state.viewMat = Mat3x3f{.m={
                {1.0, 0.0, 0.0},
                {0.0, 1.0, 0.0},
                {0.0, 0.0, 1.0},
        }};
        state.ww240_viewRange = 240.0;
        state.leftRight.x = (float) ((int) (466 * gwidth) / 640);  // left = 0,728125
        state.leftRight.y = (float) ((int) (594 * gheight) / 480);  // right = 1,2375
        state.topBottom.x = (float) ((int) (33 * gwidth) / 640);  // top = 0,0515625
        state.topBottom.y = (float) ((int) (225 * gheight) / 480);  // bottom = 0,46875
        state.farPlane = 10.0;
        state.flags |= 4;

        engine_setRenderArea(
                (__int64) state.leftRight.x,
                (__int64) state.topBottom.x,
                (__int64) (state.leftRight.y - state.leftRight.x),
                (__int64) (state.topBottom.y - state.topBottom.x)
        );
    } else if (cam->_mode == 0x12) {  // moving anim
        int idx = cam->animIdx;

        Vec3f vecFrom = cam->vec3Buf[idx] + cam->fEB2;
        Vec3f vecTo = cam->vec3Buf[idx + 1] + cam->fEB2;

        Vec3f interpVec;
        static_Vec3f_interpolate(
                &interpVec,
                vecFrom.x, vecFrom.y, vecFrom.z,
                vecTo.x, vecTo.y, vecTo.z,
                cam->moveInterpolationFactor);

        Mat3x3f matFrom = cam->matBuf[idx];
        Mat3x3f matTo = cam->matBuf[idx + 1];

        Mat3x3f interpMat;
        Mat3x3f_lerp(
                &interpMat,
                matFrom.m[0][0], matFrom.m[0][1], matFrom.m[0][2],
                matFrom.m[1][0], matFrom.m[1][1], matFrom.m[1][2],
                matFrom.m[2][0], matFrom.m[2][1], matFrom.m[2][2],
                matTo.m[0][0], matTo.m[0][1], matTo.m[0][2],
                matTo.m[1][0], matTo.m[1][1], matTo.m[1][2],
                matTo.m[2][0], matTo.m[2][1], matTo.m[2][2],
                cam->moveInterpolationFactor);

        double fovFrom = cam->buf1[idx];
        double fovTo = cam->buf1[idx + 1];
        double interpFov = (fovTo - fovFrom) * cam->moveInterpolationFactor + fovFrom;
        long double fieldOfView = std::tan(interpFov * 0.5);

        float zoomFrom = cam->buf2[idx];
        float zoomTo = cam->buf2[idx + 1];
        float interpZoom = (zoomTo - zoomFrom) * cam->moveInterpolationFactor + zoomFrom;

        state.v3f = interpVec - Vec3f { 0.f, 0.f, 1.f, };
        state.viewMat = interpMat;
        state.ww240_viewRange = (double) MyWindow_instance.dwWidth / (fieldOfView + fieldOfView);

        state.farPlane = interpZoom * 0.0020000001;

        state.flags = (1 * (cam->sub_44AA20() & 1)) | (state.flags & ~1u);
        state.flags = (2 * (cam->sub_44AB60() & 1)) | (state.flags & ~2u);
        state.flags = (4 * (cam->sub_44AC80() & 1)) | (state.flags & ~4u);
        state.flags = (8 * (cam->sub_44AA80() & 1)) | (state.flags & ~8u);
    } else {
        Vec3q12 q12vec = cam->location + cam->locationOffset;

        int try_level = 0;

        Q12 fov = cam->fovD8E * Q12_encode(320);

        try_level = 2;

        float aspect = 640.f / (float) MyWindow_instance.dwWidth;
        Vec3f a2a { 0.0, 0.0, Q12_decode(cam->curZoomLevel) * aspect * -1.f };

        state.v3f = (transpose(cam->matrix) * a2a) + (Q12_decode(q12vec) * Vec3f{1.f, 1.f, -1.f});
        state.viewMat = cam->matrix;
        state.ww240_viewRange = Q12_decode(fov);
        state.flags = (1 * (cam->sub_44AA20() & 1)) | (state.flags & ~1u);
        state.flags = (2 * (cam->sub_44AB60() & 1)) | (state.flags & ~2u);
        state.flags = (4 * (cam->sub_44AC80() & 1)) | (state.flags & ~4u);
        state.flags = (8 * (cam->sub_44AA80() & 1)) | (state.flags & ~8u);
        state.farPlane = cam->sub_44D550();

        try_level = -1;
    }
    MyCameraState_applyToGlobalState(&state, args->tickPercent256 / 256.);
    if (cam->_mode == 7) {
        enableSmth_578DE0();

        double posX_ = 466 * g_cgui_manager_width_6CE590 / 640;
        double right = 594 * g_cgui_manager_width_6CE590 / 640;

        double posY_ = 33 * g_cgui_manager_height_6CD190 / 480;
        double bottom = 225 * g_cgui_manager_height_6CD190 / 480;

        Vec3f vec1 {1.0, 1.0, 1.0 };
        CEngine2DSprite_create(
                (int64_t) posX_, (int64_t) posY_, (int64_t) (right - posX_), (int64_t) (bottom - posY_),
                0.5, g_idx, vec1, 1.0, 0.0, 0
        );
        disableSmth();
    }
    ++this_->updateCount;
    g_timeMs79570C = g_timeMs795710;
    g_timeMs795710 = getTimeMs();
    return 1;
}

void __cdecl dk2::MyCameraState_applyToGlobalState(MyCameraState *pState, float a2_interpolationFactor) {
    g_activeCameraState.v3f = pState->v3f;
    g_activeCameraState.viewMat = pState->viewMat;
    g_activeCameraState.ww240_viewRange = pState->ww240_viewRange;
    g_activeCameraState.leftRight = pState->leftRight;
    g_activeCameraState.topBottom = pState->topBottom;
    g_activeCameraState.trg = pState->trg;
    g_activeCameraState.farPlane = pState->farPlane;
    g_activeCameraState.flags ^= (LOBYTE(g_activeCameraState.flags) ^ (uint8_t) (pState->flags << 31 >> 31)) & 1;
    g_activeCameraState.flags ^= (LOBYTE(g_activeCameraState.flags) ^ (uint8_t) (pState->flags << 30 >> 30)) & 2;
    g_activeCameraState.flags ^= (LOBYTE(g_activeCameraState.flags) ^ (uint8_t) (pState->flags << 29 >> 29)) & 4;
    g_activeCameraState.flags ^= (LOBYTE(g_activeCameraState.flags) ^ (uint8_t) (pState->flags << 28 >> 28)) & 8;

    int flags = g_activeCameraState.flags;
    if ((flags & 1) != 0 && g_activeCameraState.farPlane > 32.0)
        g_activeCameraState.farPlane = 32.0;

    shad_dword_780E68 = 0;
    ScreenObjectArr_instance.itemsCount = 0;

    g_activeCameraState.trg.x = (g_activeCameraState.leftRight.x + g_activeCameraState.leftRight.y) * 0.5;
    g_activeCameraState.trg.y = (g_activeCameraState.topBottom.x + g_activeCameraState.topBottom.y) * 0.5;

    if (g_activeCameraState.topBottom.y - g_activeCameraState.topBottom.x <= 32.0) return;

    g_interpolationFactor = a2_interpolationFactor;
    g_flags_760B84 = flags << 29 >> 31;
    g_flags_760B60 = flags << 30 >> 31;

    g_v3f_x_760B48 = strangeOptimizedMultiplyAddCast(g_activeCameraState.v3f.x, 1.f, 0.f);
    g_64sub_v3f_x_760AAC = 64 - g_v3f_x_760B48;

    g_v3f_y_760B50 = strangeOptimizedMultiplyAddCast(g_activeCameraState.v3f.y, 1.f, 0.f);
    g_64sub_v3f_y_764BE0 = 64 - g_v3f_y_760B50;

    MyDLVec2i *pMyDlVec = computeFrustumContour2D();
    MyCameraState_computeProjectionMat(&g_activeCameraState);
    setupDepthCoefficients(0, g_viewZMin - 1.0, g_viewZMax + 1.0, 0.1, 1.0, 1);

    g_depthMode_7820A0 = 0;
    setBoundaries_58A4F0(
            g_activeCameraState.leftRight.x,
            g_activeCameraState.leftRight.y,
            g_activeCameraState.topBottom.x,
            g_activeCameraState.topBottom.y);

    if ((g_activeCameraState.flags & 1) != 0)
        MyDLVec2i_static_sub_5737E0(pMyDlVec);
    else
        MyDLVec2i_static_sub_5735A0(pMyDlVec);
    if (pMyDlVec) {
        MyDLVec2i *fC_next = pMyDlVec->next;
        if (fC_next && fC_next != pMyDlVec) {
            MyDLVec2i *v8;
            do {
                v8 = fC_next->next;
                fC_next->next = NULL;
                if (fC_next)
                    fC_next->sub_575D20(1);
                fC_next = v8;
            } while (v8 != pMyDlVec);
        }
        MyHeap_free(pMyDlVec);
    }

    static_createMeshes_p();
    if (g_unused7651F0) {
        throw std::exception("unexpected");
//        auto *v9 = g_unused7651F0;
//        void (__thiscall ***v10)(DWORD, int); // ecx
//        v10 = (void (__thiscall ***)(DWORD, int))*((DWORD *)g_unused7651F0 + 2);
//        if ( v10 )
//            (**v10)(v10, 1);
//        DWORD *v11 = (DWORD *)v9[3];
//        if ( v11 )
//            sub_5746B0(v11, 1);
//        MyHeap_free(v9);
    }
    g_unused7651F0 = 0;
    static_g_NewObj571B3B_sub_576230();
    appendAllToSceneObject2EList();
}
