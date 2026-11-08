//
// Created by DiaLight on 7/23/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/world/CEngineAnimMesh.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/primitive/resource/CAnimMeshResource.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/MyMeshResourceHolder.h"
#include "dk2/utils/Uv2f.h"
#include "tools/visual_debug.h"
#include "dk2/LightSplatBuffer.h"
#include "dk2/math/vec.h"
#include "dk2/math/color.h"
#include "dk2/MeshVertEx.h"
#include "dk2/Obj571B47.h"
#include "dk2/Obj599A8D.h"
#include "dk2/SprsAnimHeader.h"
#include "dk2/AnimVertEx.h"
#include "dk2/utils/Idx3ub.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "patches/opengl/visual_value.h"


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

}

void dk2::CEngineAnimMesh::_addRenderObj(int a1, SceneObject2E *a2) {
    if (a1 >= 2000) {
        this->addRenderObj_ge2000(a1 - 2000, a2);
        return;
    }
    if (a1 >= 1000) {
        this->addRenderObj_lt2000(a1 - 1000, a2);
        return;
    }
    this->addRenderObj_lt1000(a1, a2);
}

void dk2::CEngineAnimMesh::addRenderObj_lt1000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.AnimMesh_lt1000::disable");
    if (disable) return;

    CAnimMeshResource *Resource = (CAnimMeshResource *) MyMeshResourceHolder_getResource(this->f50_pMeshHolder);

    SprsAnimHeader *pHeader = &Resource->buf[a2];
    MyScaledSurface *v5 = MyEntryBuf_MyScaledSurface_getByIdx(pHeader->MyScaledSurface_idx);
    __renderFun_setSceneObject2E(
            a3,
            1,
            &this->f10_matrix,
            &this->f4_vec4,
            this->f38__diffusionAlpha,
            this->f48_flags & 0x10000);

    LightSplatBuffer v63;
    v63.count = 0;

    Color3f color = v5->color21 + this->f3C_color3C;

    Vec3f v45;
    this->f10_matrix.multiplyVec(&v45, &Resource->pos);
    if ((a3->renderFlags_x2[0] & RenderState_useLightSplat) != 0) {
        v63.build(
                this->f58_pObj571B47,
                this->field_68,
                this->f10_matrix,
                this->f4_vec4 + v45);
    }
    for (int i = 0; i < pHeader->lod_list[this->field_78]; ++i) {
        Idx3ub tri = pHeader->plod_list[this->field_78][i];

        if (!g_vertexFlags[tri.i]) {
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.i, &g_vec_766A78[tri.i]);
            g_RenderData_addViewProj(tri.i, &g_vec_766A78[tri.i]);
        }
        if (!g_vertexFlags[tri.j]) {
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.j, &g_vec_766A78[tri.j]);
            g_RenderData_addViewProj(tri.j, &g_vec_766A78[tri.j]);
        }
        if (!g_vertexFlags[tri.k]) {
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.k, &g_vec_766A78[tri.k]);
            g_RenderData_addViewProj(tri.k, &g_vec_766A78[tri.k]);
        }
        g_RenderData_apply(tri.i, tri.j, tri.k);

        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) {
            AnimVertEx *v24 = &pHeader->AnimVertEx_base[tri.i];
            if (g_vertexFlags[tri.i])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.i, &g_vec_766A78[tri.i]);

            Vec3f a3a = g_vec_766A78[tri.i] - v45;
            Color3f a2a = color;
            v63.accumulatePreBaked(&a2a, &a3a, &v24->vec);

            Uv2f uv = UQ15_to_Uv2f(v24->uv);
            g_Vertex_setColorUv(tri.i, &a2a, &uv);
        }
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) {
            AnimVertEx *v28 = &pHeader->AnimVertEx_base[tri.j];
            if (g_vertexFlags[tri.j])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.j, &g_vec_766A78[tri.j]);

            Vec3f v62 = g_vec_766A78[tri.j] - v45;
            Color3f a2a = color;
            v63.accumulatePreBaked(&a2a, &v62, &v28->vec);

            Uv2f uv = UQ15_to_Uv2f(v28->uv);
            g_Vertex_setColorUv(tri.j, &a2a, &uv);
        }
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) {
            AnimVertEx *v31 = &pHeader->AnimVertEx_base[tri.k];
            if (g_vertexFlags[tri.k])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.k, &g_vec_766A78[tri.k]);

            Vec3f v50 = g_vec_766A78[tri.k] - v45;
            Color3f a2a = color;
            v63.accumulatePreBaked(&a2a, &v50, &v31->vec);

            Uv2f uv = UQ15_to_Uv2f(v31->uv);
            g_Vertex_setColorUv(tri.k, &a2a, &uv);
        }
    }
    applyIndxs_sub_58AC20();
    this->f50_pMeshHolder->markUsed();
}

void dk2::CEngineAnimMesh::addRenderObj_lt2000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.AnimMesh_lt2000::disable");
    if (disable) return;

    CAnimMeshResource *Resource = (CAnimMeshResource *) MyMeshResourceHolder_getResource(this->f50_pMeshHolder);
    int v6 = this->f48_flags & 0x10000;
    SprsAnimHeader *pHeader = &Resource->buf[a2];

    float f38__diffusionAlpha = this->f38__diffusionAlpha;
    Mat3x3f &p_f10_matrix = this->f10_matrix;
    __renderFun_setSceneObject2E(a3, 1, &this->f10_matrix, &this->f4_vec4, f38__diffusionAlpha, v6);
    float f1D_colorMult = MyEntryBuf_MyScaledSurface_getByIdx(pHeader->MyScaledSurface_idx)->colorMult;

    LightSplatBuffer v118;
//    for (int i = 0; i < 24; ++i) {
//        ret_this_0args(&v118.items[i]);
//    }
    v118.count = 0;
    Color3f color = this->f3C_color3C;

    Vec3f v74 = p_f10_matrix * Resource->pos;
    if ((this->f48_flags & 4) == 0) {
        v118.build(this->f58_pObj571B47, this->field_68, p_f10_matrix, this->f4_vec4 + v74);
    }

    for (int i = 0; i < pHeader->lod_list[this->field_78]; ++i) {
        Idx3ub tri = pHeader->plod_list[this->field_78][i];

        if (!g_vertexFlags[tri.i]) {
            Vec3f *a3a = &g_vec_766A78[tri.i];
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.i, a3a);
            g_RenderData_addViewProj(tri.i, a3a);
        }
        if (!g_vertexFlags[tri.j]) {
            Vec3f *a3a = &g_vec_766A78[tri.j];
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.j, a3a);
            g_RenderData_addViewProj(tri.j, a3a);
        }
        if (!g_vertexFlags[tri.k]) {
            Vec3f *a3a = &g_vec_766A78[tri.k];
            Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.k, a3a);
            g_RenderData_addViewProj(tri.k, a3a);
        }
        g_RenderData_apply(tri.i, tri.j, tri.k);
        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) {
            Vec3f *a3a = &pHeader->AnimVertEx_base[tri.i].vec;
            if (g_vertexFlags[tri.i])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.i, &g_vec_766A78[tri.i]);

            Vec3f v72 = norm(g_activeCameraState.viewMat * (p_f10_matrix * g_vec_766A78[tri.i] + this->f4_vec4 - g_activeCameraState.v3f));

            Vec3f v82 = p_f10_matrix * *a3a * 0.5;

            Vec3f v99 = g_vec_766A78[tri.i] - v74;
            Color3f v63 = color;
            v118.accumulatePreBaked(&v63, &v99, a3a);
            v63 = v63 * f1D_colorMult;

            Uv2f v93;
            v93.u = v82.z * v72.x - v82.x * v72.z - -0.5;
            v93.v = v82.z * v72.y - v82.y * v72.z - -0.5;
            g_Vertex_setColorUv(tri.i, &v63, &v93);
        }
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) {
            Vec3f *a3a = &pHeader->AnimVertEx_base[tri.j].vec;
            if (g_vertexFlags[tri.j])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.j, &g_vec_766A78[tri.j]);

            Vec3f v73 = norm(g_activeCameraState.viewMat * (p_f10_matrix * g_vec_766A78[tri.j] + this->f4_vec4 - g_activeCameraState.v3f));

            Vec3f v85 = p_f10_matrix * *a3a * 0.5;

            Vec3f v96 = g_vec_766A78[tri.j] - v74;
            Color3f v63 = color;
            v118.accumulatePreBaked(&v63, &v96, a3a);
            v63.r = v63.r * f1D_colorMult;
            v63.g = v63.g * f1D_colorMult;
            v63.b = v63.b * f1D_colorMult;

            Uv2f v95;
            v95.u = v85.z * v73.x - v85.x * v73.z - -0.5;
            v95.v = v85.z * v73.y - v85.y * v73.z - -0.5;
            g_Vertex_setColorUv(tri.j, &v63, &v95);
        }
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) {
            Vec3f *p_f0_vec = &pHeader->AnimVertEx_base[tri.k].vec;
            if (g_vertexFlags[tri.k])
                Resource->sub_57E5B0(a2, this->field_60, (__int64) (double) this->field_64, tri.k, &g_vec_766A78[tri.k]);

            Vec3f v71 = norm(g_activeCameraState.viewMat * (p_f10_matrix * g_vec_766A78[tri.k] + this->f4_vec4 - v74 - g_activeCameraState.v3f));

            Vec3f v88 = p_f10_matrix * *p_f0_vec * 0.5;

            Color3f v63 = color;
            v118.accumulatePreBaked(&v63, &g_vec_766A78[tri.k], p_f0_vec);
            v63 = v63 * f1D_colorMult;

            Uv2f v94;
            v94.u = v88.z * v71.x - v88.x * v71.z - -0.5;
            v94.v = v88.z * v71.y - v88.y * v71.z - -0.5;
            g_Vertex_setColorUv(tri.k, &v63, &v94);
        }
    }
    applyIndxs_sub_58AC20();
    this->f50_pMeshHolder->markUsed();
}

void dk2::CEngineAnimMesh::addRenderObj_ge2000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.AnimMesh_ge2000::disable");
    if (disable) return;

    CAnimMeshResource *Resource = (CAnimMeshResource *) MyMeshResourceHolder_getResource(this->f50_pMeshHolder);
    Obj599A8D *v10 = this->f58_pObj571B47->pObj599A8D_x12[this->f7C_obj58EC70.arrA[a2]];

    Vec3f v18 = this->f10_matrix * Resource->pos + this->f4_vec4;
    Vec3f v12 = v18 - v10->vec8;
    long double v15 = sqrt(v12.x * v12.x + v12.y * v12.y) * 3.1415927;
    SceneObject2E_addRenderObj(
            a3, &v10->vec8,
            v15 * 0.25 * 1.5 / 2.5,
            v10->_one, &v18,
            Resource->cubeScale * this->field_5C,
            &this->f7C_obj58EC70
    );
    this->f50_pMeshHolder->markUsed();
}


