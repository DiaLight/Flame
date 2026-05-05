//
// Created by DiaLight on 4/4/2026.
//
#include "dk2/engine/primitive/CEngine2DMeshSurface.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/utils/Vec2f.h"
#include "dk2/utils/Vec3s.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include <cmath>
#include <algorithm>


int __cdecl dk2::CEngine2DMeshSurface_create(
        int a1_16xbuf_count,
        int a2_indices_count,
        dk2::Vec2f *a3_16xbuf,
        dk2::Vec3s *a4_indices,
        float a5_z,
        int a6,
        Vec3f *a7_vec,
        float a8,
        int a9_flags) {
    while (true) {
        CEngine2DMeshSurface *newObj = (CEngine2DMeshSurface *)MyHeap_alloc(sizeof(CEngine2DMeshSurface));
        int try_level = 0;
        CEnginePrimitiveBase *obj;
        if ( newObj )
            obj = newObj->constructor(
                    a1_16xbuf_count,
                    a2_indices_count,
                    a3_16xbuf,
                    a4_indices,
                    a5_z,
                    a7_vec,
                    a9_flags);
        else
            obj = NULL;
        obj->f0_parent = g_pCEngine2DPrimitive;
        try_level = -1;
        g_pCEngine2DPrimitive = obj;
        MyScaledSurface *scaledSurf = MyEntryBuf_MyScaledSurface_getByIdx(a6);

        int scaleIdx;
        {
//            int f15_prob_height = scaledSurf->prob_height;
//            float v19 = (double)f15_prob_height * a8 - -0.0009765625 - 0.49998999 - -12582912.0;
//            int scaleIdx = (LODWORD(v19) & 0x7FFFFF) - 0x400000;
//            if ( scaleIdx < 0 ) scaleIdx = 0;
//            if ( scaleIdx >= f15_prob_height ) scaleIdx = f15_prob_height - 1;

            // above is optimized version of
            scaleIdx = std::clamp<int>(
                    std::round((double) scaledSurf->prob_height * a8),
                    0, scaledSurf->prob_height - 1
            );
        }
        int fC_drawFlags = scaledSurf->drawFlags;
        MyCESurfHandle *surf = scaledSurf->scaledSurfArr[scaleIdx].surfScaledArr[0];
        uint32_t v20;
        uint32_t v21;
        transformFlags(a9_flags, &v20, &v21);
        uint32_t v16 = v21 | fC_drawFlags & v20;
        if ( (MyDirectDraw_instance.flags & 1) != 0 )
            v16 = v16 & ~0x300u | 0x200;
        MyCESurfHandle_static_addToHashList_flagsOr400(surf, v16);
        if ( a2_indices_count ) {
            int idx = SceneObject2E_count;
            if ( SceneObject2E_count >= SceneObject2EList_instance.maxCount ) {
                SceneObject2EList_instance.objects2EToDraw_enlarge(SceneObject2E_count);
                idx = SceneObject2E_count;
            }
            SceneObject2E &sobj = SceneObject2EList_instance.arr[idx];
            sobj.mesh = obj;
            sobj.f2C_ = 0;
            sobj.lod__triangleCount = a2_indices_count;
            sobj.numVertsEx = a1_16xbuf_count;
            sobj.drawFlags_x2[0] = v16;
            sobj.renMode = g_renMode_7820A0;
            sobj.surfhCount = 1;
            sobj.propsCount = 1;
            sobj.numTextureSamplers_x2[0] = 1;
            sobj.surfh_x4[0] = surf;
            sobj.zeroOrM1 = 0;
            SceneObject2E_count++;
        }
        int result = a9_flags;
        if ( (a9_flags & 0x40) == 0 )
            return result;
        a9_flags = a9_flags & ~0x42 | 2;
    }
}

