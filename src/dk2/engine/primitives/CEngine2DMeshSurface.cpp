//
// Created by DiaLight on 4/4/2026.
//
#include "dk2/engine/primitive/CEngine2DMeshSurface.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/utils/Vec2f.h"
#include "dk2/utils/Vec3us.h"
#include "dk2/math/vec.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/utils/Idx3us.h"
#include "tools/visual_debug.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "patches/opengl/visual_value.h"
#include <cmath>


int __cdecl dk2::CEngine2DMeshSurface_create(
        int a1_16xbuf_count,
        int a2_indices_count,
        dk2::Vec2f *a3_16xbuf,
        dk2::Vec3us *a4_indices,
        float a5_z,
        int a6,
        Vec3f *a7_vec,
        float a8,
        int a9_flags) {
    while (true) {
        CEngine2DMeshSurface *newObj = (CEngine2DMeshSurface *) MyHeap_alloc(sizeof(CEngine2DMeshSurface));
        int try_level = 0;
        CEnginePrimitiveBase *obj;
        if (newObj) {
            obj = newObj->constructor(
                    a1_16xbuf_count,
                    a2_indices_count,
                    a3_16xbuf,
                    a4_indices,
                    a5_z,
                    a7_vec,
                    a9_flags);
        } else {
            obj = NULL;
        }
        obj->f0_byConstructor_prev = g_Meshes2D_byConstructor_last;
        try_level = -1;
        g_Meshes2D_byConstructor_last = obj;
        MyScaledSurface *scaledSurf = MyEntryBuf_MyScaledSurface_getByIdx(a6);

        int scaleIdx = strangeOptimizedMultiplyAddCast((float) scaledSurf->prob_height, a8, 0.0009765625);
        if (scaleIdx < 0) scaleIdx = 0;
        if (scaleIdx > (scaledSurf->prob_height - 1)) scaleIdx = scaledSurf->prob_height - 1;

        int renderFlags = scaledSurf->renderFlags;
        MyCESurfHandle *surf = scaledSurf->scaledSurfArr[scaleIdx].surfScaledArr[0];
        uint32_t _mask;
        uint32_t _flags;
        transformFlags(a9_flags, &_mask, &_flags);
        uint32_t _renderFlags = _flags | renderFlags & _mask;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0)
            _renderFlags = _renderFlags & ~RenderState_zEnable | RenderState_use3DPipeline;
        MyCESurfHandle_static_addToHashList_flagsOr400(surf, _renderFlags);
        if (a2_indices_count) {
            int idx = SceneObject2E_count;
            if (SceneObject2E_count >= SceneObject2EList_instance.maxCount) {
                SceneObject2EList_instance.enlarge(SceneObject2E_count);
                idx = SceneObject2E_count;
            }
            SceneObject2E &sobj = SceneObject2EList_instance.arr[idx];
            sobj.mesh = obj;
            sobj.f2C_ = 0;
            sobj.lod__triangleCount = a2_indices_count;
            sobj.numVertsEx = a1_16xbuf_count;
            sobj.renderFlags_x2[0] = _renderFlags;
            sobj.currentDepthMode = g_depthMode_7820A0;
            sobj.surfhCount = 1;
            sobj.texStagesCount = 1;
            sobj.numTextureSamplers_x2[0] = 1;
            sobj.surfh_x4[0] = surf;
            sobj.zeroOrM1 = 0;
            SceneObject2E_count++;
        }
        int result = a9_flags;
        if ((a9_flags & 0x40) == 0)
            return result;
        a9_flags = a9_flags & ~0x42 | 2;
    }
}


void dk2::CEngine2DMeshSurface::_addRenderObj(int a2, SceneObject2E *a1) {
    static VisualBool disable("CEngine.2DMeshSurface::disable");
    if(disable) return;

    __renderFun_setSceneObject2E(a1, 0, NULL, NULL, 1.0, 0);

    Color3f color = this->f18_color18;
    for (int i = 0; i < this->f10_indices_count; ++i) {
        Idx3us &tri = this->f8_indices[i];

        Vec2f *vec2dI = &this->f4_16xbuf[2 * tri.i];
        Vec2f *vec2dJ = &this->f4_16xbuf[2 * tri.j];
        Vec2f *vec2dK = &this->f4_16xbuf[2 * tri.k];

        Vec3f vecI {vec2dI->x, vec2dI->y, this->f14_z };
        g_RenderData_addZCapped(tri.i, &vecI);

        Vec3f vecJ {vec2dJ->x, vec2dJ->y, this->f14_z };
        g_RenderData_addZCapped(tri.j, &vecJ);

        Vec3f vecK {vec2dK->x, vec2dK->y, this->f14_z };
        g_RenderData_addZCapped(tri.k, &vecK);

        g_RenderData_apply(tri.i, tri.j, tri.k);

        Uv2f uvI {vec2dI[1].x, vec2dI[1].y };
        Uv2f uvJ {vec2dJ[1].x, vec2dJ[1].y };
        Uv2f uvK {vec2dK[1].x, vec2dK[1].y };

        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.i, &color, &uvI);
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.j, &color, &uvJ);
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.k, &color, &uvK);
    }
    applyIndxs_sub_58AC20();
}

