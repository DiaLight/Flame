//
// Created by DiaLight on 7/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicHeightField.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/utils/Color3ub.h"
#include "tools/visual_debug.h"
#include "dk2/LightSplatBuffer.h"
#include "dk2/math/vec.h"
#include "dk2/math/color.h"
#include "dk2/math/uv.h"
#include "dk2/MeshVertEx.h"
#include "dk2/Obj571B47.h"
#include "dk2/Obj599A8D.h"
#include "dk2/AppendObject2EArgs.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "patches/opengl/visual_value.h"
#include <sstream>


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

    inline void l_RenderData_addViewProj(uint32_t idx, const Vec3f &vec) {
        g_RenderData_addViewProj(idx, (Vec3f *) &vec);
    }
    
}


dk2::CEngineDynamicHeightField *dk2::CEngineDynamicHeightField::constructor(
        Vec3f *a2_loc,
        int a3_count,
        float *a4_arr2,
        const void *a5_arr3,
        int a6_worldEntry_idx,
        int a7_bump_map,
        int a8_env_map,
        int a9_flags,
        float a10__diffuseAlpha,
        Color3f *a11_pColor,
        float a12_animInterpolationFactorC1) {
    ((CEngineWorldPrimitive *) this)->constructor();
    *(void **) this = CEngineDynamicHeightField::vftable;
    int v13 = (a3_count + 1) * (a3_count + 1);
    this->f1C_loc = *a2_loc;
    this->f8_pVec3f_arr = (Vec3f *) MyHeap_alloc(12 * v13);
    this->field_C = (float *) MyHeap_alloc(4 * v13);
    memcpy(this->f8_pVec3f_arr, a5_arr3, 4 * ((unsigned int) (12 * v13) >> 2));

    float min_val = 1.0e30;
    float max_val = -1.0e30;
    for (int i = 0; i < v13; ++i) {
        double val = a4_arr2[i] + this->f1C_loc.z;
        this->field_C[i] = val;
        if (val < min_val) min_val = val;
        if (val > max_val) max_val = val;
    }
    this->f28_vec28.x = this->f1C_loc.x - -0.5;
    this->f28_vec28.y = this->f1C_loc.y - -0.5;
    this->f28_vec28.z = (max_val + min_val) * 0.5;
    this->f4_count4 = a3_count;
    this->f10_worldEntry_idx = a6_worldEntry_idx;
    this->f34__diffuseAlpha = a10__diffuseAlpha;
    this->f14_bump_map = a7_bump_map;
    this->f18_env_map = a8_env_map;
    this->f38_flags38 = a9_flags;
    this->f3C_color3C = *a11_pColor;
    this->f3C_color3C.r = this->f3C_color3C.r * 255.0;
    this->f3C_color3C.g = this->f3C_color3C.g * 255.0;
    this->f3C_color3C.b = this->f3C_color3C.b * 255.0;
    this->f48_animInterpolationFactorC1 = a12_animInterpolationFactorC1;
    return this;
}


void dk2::CEngineDynamicHeightField::appendToSceneObject2EList(AppendObject2EArgs *a2_) {  // broken!!!
    {
        double maxValue = -1.0e30;
        float minValue = 1.0e30;
        int v4 = this->f4_count4 + 1;
        for (int y = 0; y < v4; ++y) {
            for (int x = 0; x < v4; ++x) {
                float &value = this->field_C[y * v4 + x];
                if (value < (double) minValue) minValue = value;
                if (value > maxValue) maxValue = value;
            }
        }
    }

    Vec3f v41 = g_activeCameraState.viewMat * ((this->f1C_loc + Vec3f {0.5f, 0.5f, 0}) - g_activeCameraState.v3f);
    float a2a;
    Vec3f v43;
    Vec3f_static_sub_575F10(&v41, 1.0, &v43, &a2a);

    this->f4C_pObj571B47 = a2_->pObj571B47;
    MyScaledSurface *v9_diffuseTex = MyEntryBuf_MyScaledSurface_getByIdx(this->f10_worldEntry_idx);
    int v10 = MyScaledSurface_sub_57F030(v9_diffuseTex, a2a, 1.0);
    MyCESurfHandle *v11_diffuseSH = v9_diffuseTex->sub_581B80(v10, this->f48_animInterpolationFactorC1, 0);
    MyCESurfHandle_static_addToHashList_flagsOr400(v11_diffuseSH, v9_diffuseTex->renderFlags);

    uint32_t _flags;
    uint32_t _mask;
    transformFlags(this->f38_flags38, &_mask, &_flags);
    unsigned int renderState = _flags | v9_diffuseTex->renderFlags & _mask;
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingSimpleEnabled) != 0 && (this->f38_flags38 & 0x8000) != 0) {
        MyScaledSurface *v14_envTex = MyEntryBuf_MyScaledSurface_getByIdx(this->f18_env_map);
        MyScaledSurface *v15_bumpTex = MyEntryBuf_MyScaledSurface_getByIdx(this->f14_bump_map);

        uint32_t f15_prob_height = v14_envTex->prob_height;
        float a2 = (double) (int) f15_prob_height * this->f48_animInterpolationFactorC1
                         - -0.0009765625
                         - 0.49998999
                         - -12582912.0;
        signed int v17 = ((unsigned int) a2 & 0x7FFFFF) - 0x400000;
        if (v17 < 0) v17 = 0;
        if (v17 >= (int) f15_prob_height) v17 = f15_prob_height - 1;
        MyCESurfHandle *v20_envSH = v14_envTex->scaledSurfArr[v17].surfScaledArr[0];

        uint32_t v18_bumpTexProbHeight = v15_bumpTex->prob_height;
        a2 = (double) (int) v18_bumpTexProbHeight * this->f48_animInterpolationFactorC1 - -0.0009765625 - 0.49998999 - -12582912.0;
        signed int v21 = ((unsigned int) a2 & 0x7FFFFF) - 0x400000;
        if (v21 < 0) v21 = 0;
        if (v21 >= (int) v18_bumpTexProbHeight) v21 = v18_bumpTexProbHeight - 1;
        MyCESurfHandle *v22_bumpSH = v15_bumpTex->scaledSurfArr[v21].surfScaledArr[0];

        MyCESurfHandle_static_addToHashList(v20_envSH, 0);
        MyCESurfHandle_static_addToHashList(v22_bumpSH, 2);
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingLuminanceEnabled) != 0) {
            renderState |= RenderState_bumpMapLuminance;
        } else {
            renderState |= RenderState_bumpMapSimple;
        }

        MyCESurfHandle *surfh_x3[] {
                v11_diffuseSH,
                v22_bumpSH,
                v20_envSH,
        };

        int f4_count4 = this->f4_count4;
        uint16_t vertexCount = (f4_count4 + 1) * (f4_count4 + 1);
        int triangleCount = 2 * f4_count4 * f4_count4;
        if (triangleCount) {
            if (SceneObject2E_count >= SceneObject2EList_instance.maxCount) {
                SceneObject2EList_instance.enlarge(SceneObject2E_count);
            }
            SceneObject2EList_instance.arr[SceneObject2E_count].mesh = (CEnginePrimitiveBase *) this;
            SceneObject2EList_instance.arr[SceneObject2E_count].f2C_ = 0;
            SceneObject2EList_instance.arr[SceneObject2E_count].lod__triangleCount = triangleCount;
            SceneObject2EList_instance.arr[SceneObject2E_count].numVertsEx = vertexCount;
            SceneObject2EList_instance.arr[SceneObject2E_count].currentDepthMode = g_depthMode_7820A0;
            SceneObject2EList_instance.arr[SceneObject2E_count].texStagesCount = 1;
            SceneObject2EList_instance.arr[SceneObject2E_count].zeroOrM1 = 0;
            SceneObject2EList_instance.arr[SceneObject2E_count].renderFlags_x2[0] = renderState;
            SceneObject2EList_instance.arr[SceneObject2E_count].numTextureSamplers_x2[0] = 3;
            SceneObject2EList_instance.arr[SceneObject2E_count].surfhCount = 3;
            for (int i = 0; i < 3; ++i) {
                SceneObject2EList_instance.arr[SceneObject2E_count].surfh_x4[i] = surfh_x3[i];
            }
            ++SceneObject2E_count;
        }
    } else {
        static_appendToSceneObject2EList(
                v11_diffuseSH,
                renderState,
                (CEnginePrimitiveBase *) this,
                0,
                2 * this->f4_count4 * this->f4_count4,
                (this->f4_count4 + 1) * (this->f4_count4 + 1),
                0);
    }
}


void dk2::CEngineDynamicHeightField::_addRenderObj(int _4F0, SceneObject2E *a1) {
    static VisualBool disable("CEngine.DynamicHeightField::disable");
    if(disable) return;

    Color3f v53_color = g_color_760A98 + this->f3C_color3C;
    __renderFun_setSceneObject2E(a1, 1, NULL, NULL, this->f34__diffuseAlpha, this->f38_flags38 & 0x10000);

    float progSize = 1.0 / (double) this->f4_count4;

    LightSplatBuffer lightSplat;
    lightSplat.count = 0;
    lightSplat.constructor(this->f4C_pObj571B47, -1);

    static VisualFloat _scale("CEngineDynamicHeightField_scale", 4.f);
    float scale = 12.f;
    scale = _scale.value;

    float uvSize = progSize / scale;
    float _x_d12 = this->f1C_loc.x / scale;
    float _y_d12 = this->f1C_loc.y / scale;
    // extract float part

    float uvX_start = _x_d12 - (int32_t) _x_d12;
    float uvY_start = _y_d12 - (int32_t) _y_d12;

    int width = this->f4_count4 + 1;
    for (int y = 0; y < this->f4_count4; ++y) {
        for (int x = 0; x < this->f4_count4; ++x) {
            float locX = this->f1C_loc.x + (float) x / this->f4_count4;
            float locY = this->f1C_loc.y + (float) y / this->f4_count4;
            Uv2f progOffs {(float) x / this->f4_count4, (float) y / this->f4_count4};
            Uv2f lumOffs {uvX_start + uvSize * x, uvY_start + uvSize * y};

            int idxLT = (y + 0) * width + (x + 0);
            int idxRT = (y + 0) * width + (x + 1);
            int idxRB = (y + 1) * width + (x + 1);
            int idxLB = (y + 1) * width + (x + 0);

            if (!g_vertexFlags[idxLT]) l_RenderData_addViewProj(idxLT, Vec3f {locX, locY, this->field_C[idxLT]});
            if (!g_vertexFlags[idxRT]) l_RenderData_addViewProj(idxRT, Vec3f {locX + progSize, locY, this->field_C[idxRT]});
            if (!g_vertexFlags[idxRB]) l_RenderData_addViewProj(idxRB, Vec3f {locX + progSize, locY + progSize, this->field_C[idxRB]});
            if (!g_vertexFlags[idxLB]) l_RenderData_addViewProj(idxLB, Vec3f {locX, locY + progSize, this->field_C[idxLB]});

            if ((((BYTE) y + (BYTE) x) & 1) != 0) {
                g_RenderData_apply(idxLT, idxRT, idxRB);
                g_RenderData_apply(idxLT, idxRB, idxLB);
            } else {
                g_RenderData_apply(idxLT, idxRT, idxLB);
                g_RenderData_apply(idxRT, idxRB, idxLB);
            }

            if ((g_vertexFlags[idxLT] & Vertex_unvisitedColorUv) != 0) {
                Vec3f a3 {locX, locY, this->field_C[idxLT]};
                Vec3f &f = this->f8_pVec3f_arr[idxLT];
                Color3f a2 = v53_color;
                lightSplat.accumulateDirectionalLight(&a2, &a3, &f);
                Uv2f lumLoc = Uv2f {f.x, f.y} + 0.5f;

                Uv2f uvs[] {
                        progOffs,
                        progOffs,
                        lumLoc + lumOffs,
                };
                g_Vertex_setColorUv(idxLT, &a2, uvs);
            }
            if ((g_vertexFlags[idxRT] & Vertex_unvisitedColorUv) != 0) {
                Vec3f v82 {locX + progSize, locY, this->field_C[idxRT]};
                Vec3f &f = this->f8_pVec3f_arr[idxRT];
                Color3f a2 = v53_color;
                lightSplat.accumulateDirectionalLight(&a2, &v82, &f);
                Uv2f lumLoc = Uv2f {f.x, f.y} + 0.5f;

                Uv2f uvs[] {
                        progOffs + Uv2f {progSize, 0},
                        progOffs + Uv2f {progSize, 0},
                        lumLoc + lumOffs + Uv2f {uvSize, 0},
                };
                g_Vertex_setColorUv(idxRT, &a2, uvs);
            }
            if ((g_vertexFlags[idxRB] & Vertex_unvisitedColorUv) != 0) {
                Vec3f v85 {locX + progSize, locY + progSize, this->field_C[idxRB]};
                Vec3f &f = this->f8_pVec3f_arr[idxRB];
                Color3f a2 = v53_color;
                lightSplat.accumulateDirectionalLight(&a2, &v85, &f);
                Uv2f lumLoc = Uv2f {f.x, f.y} + 0.5f;

                Uv2f uvs[] {
                        progOffs + Uv2f {progSize, progSize},
                        progOffs + Uv2f {progSize, progSize},
                        lumLoc + lumOffs + Uv2f {uvSize, uvSize},
                };
                g_Vertex_setColorUv(idxRB, &a2, uvs);
            }
            if ((g_vertexFlags[idxLB] & Vertex_unvisitedColorUv) != 0) {
                Vec3f v89 {locX, locY + progSize, this->field_C[idxLB]};
                Vec3f &f = this->f8_pVec3f_arr[idxLB];
                Color3f a2 = v53_color;
                lightSplat.accumulateDirectionalLight(&a2, &v89, &f);
                Uv2f lumLoc = Uv2f {f.x, f.y} + 0.5f;

                Uv2f v65_uvs[] {
                        progOffs + Uv2f {0, progSize},
                        progOffs + Uv2f {0, progSize},
                        lumLoc + lumOffs + Uv2f {0, uvSize},
                };
                g_Vertex_setColorUv(idxLB, &a2, v65_uvs);
            }
        }
    }
    applyIndxs_sub_58AC20();
}


int dk2::CPCEngineInterface::createDynamicHeightField_water(
        unsigned int a2_x,
        unsigned int a3_y,
        CWorldEntry *a4_worldEntry,
        Obj448C20 *a5,
        int a6_x,
        int a7_y,
        Color3ub *a8_color,
        int a9_flags) {
    float v88_flArr[81];
    Vec3f v89_vecArr[81];

    int try_level;
    if (!MyResources_instance.video_settings.sine_wave_water) {
        Vec3f v85_vec {(float) a2_x, (float) a3_y, 0.0};

        uint32_t width = a5->size20 + 1;
        for (int y = width - 1; y >= 0; --y) {
            unsigned int v41 = a3_y * a5->size20 + y;
            for (int x = width - 1; x >= 0; --x) {
                int v46 = a5->f10 * (v41 & (a5->f14 - 1));
                int v68 = (a2_x * a5->size20 + x) & (a5->f10 - 1);
                int idx = v46 + v68;

                Vec3i &v51 = a5->pVec3i_0[idx];
                int16_t *i16Arr = a5->i16Arr;

                v88_flArr[width * y + x] = -0.8999999761581421 - (double) i16Arr[idx] / 131072.f;
                v89_vecArr[width * y + x] = norm(Vec3f {
                        v51.x / 65536.f,
                        v51.z / 65536.f,  // strange but y = z
                        v51.y / -32768.f,  // strange but z = y
                });
            }
        }

        int waterIdx = a4_worldEntry->idx;

        Color3f v83_color {
                (float) a8_color->r / 255.f,
                (float) a8_color->g / 255.f,
                (float) a8_color->b / 255.f,
        };
        float v63__diffuseAlpha = 0.69999999;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingSimpleEnabled) != 0) {
            a9_flags |= 0x8000;
            v63__diffuseAlpha = 1.0;
            waterIdx = this->bump_water;
            if (MyResources_instance.video_settings.translucent_water) a9_flags |= 1u;
        }
        CEngineDynamicHeightField *pDynHF = (CEngineDynamicHeightField *) MyHeap_alloc(0x54);
        try_level = 1;
        if (pDynHF) {
            CEnginePrimitiveBase *v33 = (CEnginePrimitiveBase *) pDynHF->constructor(
                    &v85_vec,
                    a5->size20, v88_flArr, v89_vecArr,
                    waterIdx, this->bump_water_bump_map, this->bump_water_env_map,
                    a9_flags, v63__diffuseAlpha, &v83_color,
                    this->animInterpolationFactorC1);
            try_level = -1;
            Meshes3dDynamic_byConstructor_register(v33);
            return 1;
        }
        try_level = -1;
        Meshes3dDynamic_byConstructor_register(NULL);  // probably a DK2 devs mistake
        return 1;
    } else {

        int width = a5->size20 + 1;
        Vec3f loc {(float) a2_x, (float) a3_y, 0 };
        unsigned int yShl16 = a3_y << 16;
        unsigned int xShl16 = a2_x << 16;

        int sizeShl15Y = a5->size20 << 15;
        for (int y = width - 1; y >= 0; --y) {
            __int64 preValY = (__int64) ((double) sizeShl15Y - (double) this->updateCount * -4096.0 + (double) yShl16);
            long double valY = (double) (preValY & 0x1FFFF) * 3.1415927 * 0.000015258789;
            float cosValY = cos(valY);
            float sinValY = sin(valY) * 0.03;

            int sizeShl15X = a5->size20 << 15;
            for (int x = width - 1; x >= 0; --x) {
                __int64 preValX = (__int64) ((double) sizeShl15X - (double) this->updateCount * -4096.0 + (double) xShl16);
                long double valX = (double) (preValX & 0x1FFFF) * 3.1415927 * 0.000015258789;
                float cosValX = cos(valX);
                float sinValX = sin(valX) * 0.03;

                v88_flArr[width * y + x] = -0.89999998 - (sinValX + sinValY);
                v89_vecArr[width * y + x] = norm(Vec3f {cosValX, cosValY, -3.0});

                sizeShl15X -= 0x8000;
            }
            sizeShl15Y -= 0x8000;
        }

        Color3f v83_color {
                (float) a8_color->r / 255.f,
                (float) a8_color->g / 255.f,
                (float) a8_color->b / 255.f,
        };
        CEngineDynamicHeightField *pDynHF_ = (CEngineDynamicHeightField *) MyHeap_alloc(0x54);
        try_level = 0;
        if (!pDynHF_) {
            try_level = -1;
            Meshes3dDynamic_byConstructor_register(NULL);  // probably a DK2 devs mistake
            return 1;
        }
        CEnginePrimitiveBase *v33 = (CEnginePrimitiveBase *) pDynHF_->constructor(
                &loc,
                a5->size20, v88_flArr, v89_vecArr,
                a4_worldEntry->idx, 0, 0,
                a9_flags, 0.69999999, &v83_color,
                this->animInterpolationFactorC1);
        try_level = -1;
        Meshes3dDynamic_byConstructor_register(v33);
        return 1;
    }
}

