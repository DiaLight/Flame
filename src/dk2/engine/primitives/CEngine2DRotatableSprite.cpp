//
// Created by DiaLight on 2/2/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngine2DRotatableSprite.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/math/vec.h"
#include "dk2/math/mat.h"
#include "dk2/math/color.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "tools/visual_debug.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "patches/opengl/visual_value.h"
#include <cmath>

void __cdecl dk2::CEngine2DRotatableSprite_create(
        int16_t a1_posX, int16_t a2_posY,
        int a3_x, int a4_y,
        float a5_zRotAngle, float a6_posZ, int a7_surfIdx,
        Color3f a8_color,
        float a11_x, float a12, int a13_y) {
    if (a3_x > 0 && a4_y > 0) {
        CEngine2DRotatableSprite *newObj = (CEngine2DRotatableSprite *) MyHeap_alloc(0x2C);
        CEngine2DRotatableSprite *obj = newObj;
        if (newObj) {
            ((CEngine2DPrimitive *) newObj)->constructor();
            obj->f4_x = a1_posX;
            obj->f6_y = a2_posY;
            obj->f10_z = a6_posZ;
            obj->fC_zRotAngle = a5_zRotAngle;
            *(void **) obj = CEngine2DRotatableSprite::vftable;
            obj->f8_x8 = a3_x;
            obj->fA_yA = a4_y;
            obj->f14_color14 = a8_color * 255.0;
            obj->f24_y24 = a13_y;
            obj->f20_x20__diffusionAlpha = a11_x;
        } else {
            obj = NULL;
        }
        obj->f0_byConstructor_prev = g_Meshes2D_byConstructor_last;
        g_Meshes2D_byConstructor_last = (CEnginePrimitiveBase *) obj;
        MyScaledSurface *scaledSurf = MyEntryBuf_MyScaledSurface_getByIdx(a7_surfIdx);

        int scaleIdx = strangeOptimizedMultiplyAddCast((float) scaledSurf->prob_height, a12, 0.0009765625);
        if (scaleIdx < 0) scaleIdx = 0;
        if (scaleIdx > (scaledSurf->prob_height - 1)) scaleIdx = scaledSurf->prob_height - 1;

        MyCESurfHandle *surf = scaledSurf->scaledSurfArr[scaleIdx].surfScaledArr[0];
        int renderFlags = scaledSurf->renderFlags;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0)
            renderFlags = renderFlags & ~RenderState_zEnable | RenderState_use3DPipeline;
        MyCESurfHandle_static_addToHashList_flagsOr400(surf, renderFlags);
        int idx = SceneObject2E_count;
        if (SceneObject2E_count >= SceneObject2EList_instance.maxCount) {
            SceneObject2EList_instance.enlarge(SceneObject2E_count);
            idx = SceneObject2E_count;
        }
        SceneObject2E &sobj = SceneObject2EList_instance.arr[idx];
        sobj.mesh = obj;
        sobj.f2C_ = 0;
        sobj.lod__triangleCount = 2;
        sobj.numVertsEx = 4;
        sobj.renderFlags_x2[0] = scaledSurf->renderFlags;
        sobj.currentDepthMode = g_depthMode_7820A0;
        sobj.surfhCount = 1;
        sobj.texStagesCount = 1;
        sobj.numTextureSamplers_x2[0] = 1;
        sobj.surfh_x4[0] = surf;
        sobj.zeroOrM1 = 0;
        SceneObject2E_count++;
    }
}

// rotating icon of newly discovered room
void dk2::CEngine2DRotatableSprite::_addRenderObj(int a2, SceneObject2E *a3_sceneObj) {
    this->f8_x8 /= 2;
    this->fA_yA /= 2;

    float fx = (float) this->f8_x8;
    float fy = (float) this->fA_yA;

    Mat3x3f zRotMat;
    zRotMat.init_rotationMat(2/*Z_axis*/, this->fC_zRotAngle);
    Vec3f pos = {(float) this->f4_x, (float) this->f6_y, this->f10_z};

    Vec3f leftTop = zRotMat * Vec3f {-fx, -fy, 0.0} + pos;
    Vec3f rightTop = zRotMat * Vec3f {fx, -fy, 0.0} + pos;
    Vec3f rightBottom = zRotMat * Vec3f {fx, fy, 0.0} + pos;
    Vec3f leftBottom = zRotMat * Vec3f {-fx, fy, 0.0} + pos;
    SceneObject2E_add2dSpriteRenderObj(
            a3_sceneObj,
            &leftTop, &rightTop, &rightBottom, &leftBottom,
            0.0, 0.0,
            1.0, 0.0,
            1.0, 1.0,
            0.0, 1.0,
            &this->f14_color14,
            this->f20_x20__diffusionAlpha, this->f24_y24
    );
}

void dk2::SceneObject2E_add2dSpriteRenderObj(
        SceneObject2E *a1_sceneObj,
        Vec3f *pLeftTop,
        Vec3f *pRightTop,
        Vec3f *pRightBottom,
        Vec3f *pLeftBottom,
        float a6_u2, float a7_v1,
        float a8_u1, float a9_v2,
        float a10, float a11_v2,
        float a12, float a13,
        Color3f *a14,
        float a15_diffusionAlpha,
        int a16) {
    static VisualBool disable("CEngine.2DRotatableSprite::disable");
    if(disable) return;
    __renderFun_setSceneObject2E(a1_sceneObj, 0, NULL, NULL, a15_diffusionAlpha, 0);

    g_RenderData_addZCapped(0, pLeftTop);
    g_RenderData_addZCapped(1u, pRightTop);
    g_RenderData_addZCapped(2u, pRightBottom);
    g_RenderData_addZCapped(3u, pLeftBottom);

    g_RenderData_apply(0, 1, 2);
    g_RenderData_apply(0, 2, 3);

    Uv2f uv0 {a6_u2, a7_v1 };
    Uv2f uv1 {a8_u1, a9_v2 };
    Uv2f uv2 {a10, a11_v2 };
    Uv2f uv3 {a12, a13 };

    Color3f color = *a14;
    if ((g_vertexFlags[0] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(0, &color, &uv0);
    if ((g_vertexFlags[1] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(1, &color, &uv1);
    if ((g_vertexFlags[2] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(2, &color, &uv2);
    if ((g_vertexFlags[3] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(3, &color, &uv3);

    applyIndxs_sub_58AC20();
}


