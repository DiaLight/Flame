//
// Created by DiaLight on 7/23/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicMesh.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/primitive/resource/CPolyMeshResource.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/SprsMeshHeader.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/MyMeshResourceHolder.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/utils/Idx3ub.h"
#include "tools/visual_debug.h"
#include "dk2/LightSplatBuffer.h"
#include "dk2/math/vec.h"
#include "dk2/math/color.h"
#include "dk2/MeshVertEx.h"
#include "dk2/Obj571B47.h"
#include "dk2/Obj599A8D.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "patches/opengl/visual_value.h"


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

    inline void l_RenderData_addViewProj(uint32_t idx, const Vec3f &vec) {
        g_RenderData_addViewProj(idx, (Vec3f *) &vec);
    }

}


void dk2::CEngineDynamicMesh::_addRenderObj(int a1, SceneObject2E *a2) {
    if (a1 >= 2000) {
        this->_addRenderObj_ge2000(a1 - 2000, a2);
        return;
    }
    if (a1 >= 1000) {
        this->_addRenderObj_lt2000(a1 - 1000, a2);
        return;
    }
    this->_addRenderObj_lt1000(a1, a2);
}


void dk2::CEngineDynamicMesh::_addRenderObj_lt1000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.DynamicMesh_lt1000::disable");
    if (disable) return;

    CPolyMeshResource *Resource = (CPolyMeshResource *) MyMeshResourceHolder_getResource(this->f34_pMyMeshResourceHolder);
    SprsMeshHeader *pHeader = &Resource->ptr[a2];
    MyScaledSurface *v5_surf = MyEntryBuf_MyScaledSurface_getByIdx(pHeader->MyScaledSurface_idx);
    __renderFun_setSceneObject2E(
            a3, 1, &this->f10_mat10, &this->f4_vec4,
            this->f44__diffusionAlpha, this->f4C_dflags & 0x10000
    );
    Color3f v50_color = v5_surf->color21 + this->f38_color38;

    LightSplatBuffer v75;
//    for (int i = 0; i < 24; ++i) {
//        v75.items[i];  // call emty constructor
//    }
    v75.count = 0;

    Vec3f v53_vec;
    this->f10_mat10.multiplyVec(&v53_vec, &Resource->pos);

    if ((a3->renderFlags_x2[0] & RenderState_useLightSplat) != 0) {
        v75.build(this->f58_pObj571B47, this->field_5C, this->f10_mat10, this->f4_vec4 + v53_vec);
    }

    for (int i = 0; i < pHeader->triangleCount_list[this->field_6C]; ++i) {
        Idx3ub tri = pHeader->pvertice_list[this->field_6C][i];

        MeshVertEx *vertI = &pHeader->MeshVertEx_base[tri.i];
        MeshVertEx *vertJ = &pHeader->MeshVertEx_base[tri.j];
        MeshVertEx *vertK = &pHeader->MeshVertEx_base[tri.k];

        if (!g_vertexFlags[tri.i]) g_RenderData_addViewProj(tri.i, &Resource->geom_base[vertI->index]);
        if (!g_vertexFlags[tri.j]) g_RenderData_addViewProj(tri.j, &Resource->geom_base[vertJ->index]);
        if (!g_vertexFlags[tri.k]) g_RenderData_addViewProj(tri.k, &Resource->geom_base[vertK->index]);
        g_RenderData_apply(tri.i, tri.j, tri.k);

        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) {
            Color3f a2a = v50_color;
            Vec3f a3a = Resource->geom_base[vertI->index] - v53_vec;
            v75.accumulatePreBaked(&a2a, &a3a, &vertI->vec);

            Uv2f uv = UQ15_to_Uv2f(vertI->uv);
            g_Vertex_setColorUv(tri.i, &a2a, &uv);
        }
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) {
            Color3f a2a = v50_color;
            Vec3f v71 = Resource->geom_base[vertJ->index] - v53_vec;
            v75.accumulatePreBaked(&a2a, &v71, &vertJ->vec);

            Uv2f uv = UQ15_to_Uv2f(vertJ->uv);
            g_Vertex_setColorUv(tri.j, &a2a, &uv);

        }
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) {
            Color3f a2a = v50_color;
            Vec3f v59 = Resource->geom_base[vertK->index] - v53_vec;
            v75.accumulatePreBaked(&a2a, &v59, &vertK->vec);

            Uv2f uv = UQ15_to_Uv2f(vertK->uv);
            g_Vertex_setColorUv(tri.k, &a2a, &uv);
        }
    }
    applyIndxs_sub_58AC20();
    this->f34_pMyMeshResourceHolder->markUsed();
}

void dk2::CEngineDynamicMesh::_addRenderObj_lt2000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.DynamicMesh_lt2000::disable");
    if (disable) return;

    CPolyMeshResource *Resource = (CPolyMeshResource *) MyMeshResourceHolder_getResource(this->f34_pMyMeshResourceHolder);
    SprsMeshHeader *pHeader = &Resource->ptr[a2];

    __renderFun_setSceneObject2E(a3, 1, &this->f10_mat10, &this->f4_vec4, this->f44__diffusionAlpha, this->f4C_dflags & 0x10000);

    float colorMult = MyEntryBuf_MyScaledSurface_getByIdx(pHeader->MyScaledSurface_idx)->colorMult;

    Color3f color = this->f38_color38;

    LightSplatBuffer v121;
    for (int i = 0; i < 24; ++i) {
//        ret_this_0args(&v121.items[i]);
    }
    v121.count = 0;
    Vec3f v77 = this->f10_mat10 * Resource->pos;
    if ((this->f4C_dflags & 4) == 0) {
        v121.build(this->f58_pObj571B47, this->field_5C, this->f10_mat10, this->f4_vec4 + v77);
    }

    for (int i = 0; i < pHeader->triangleCount_list[this->field_6C]; ++i) {
        Idx3ub tri = pHeader->pvertice_list[this->field_6C][i];

        MeshVertEx *vertI = &pHeader->MeshVertEx_base[tri.i];
        MeshVertEx *vertJ = &pHeader->MeshVertEx_base[tri.j];
        MeshVertEx *vertK = &pHeader->MeshVertEx_base[tri.k];

        if (!g_vertexFlags[tri.i]) g_RenderData_addViewProj(tri.i, &Resource->geom_base[vertI->index]);
        if (!g_vertexFlags[tri.j]) g_RenderData_addViewProj(tri.j, &Resource->geom_base[vertJ->index]);
        if (!g_vertexFlags[tri.k]) g_RenderData_addViewProj(tri.k, &Resource->geom_base[vertK->index]);

        g_RenderData_apply(tri.i, tri.j, tri.k);
        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) {
            Vec3f normVec = norm(g_activeCameraState.viewMat * (this->f10_mat10 * Resource->geom_base[vertI->index] + this->f4_vec4 - g_activeCameraState.v3f));
            Vec3f uvVec1 = this->f10_mat10 * vertI->vec * 0.5;

            Vec3f a3a = Resource->geom_base[vertI->index] - v77;

            Color3f col = color;
            v121.accumulatePreBaked(&col, &a3a, &vertI->vec);
            col = col * colorMult;

            Uv2f uv;
            uv.u = uvVec1.z * normVec.x - uvVec1.x * normVec.z - -0.5;
            uv.v = uvVec1.z * normVec.y - uvVec1.y * normVec.z - -0.5;
            g_Vertex_setColorUv(tri.i, &col, &uv);
        }
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) {
            Vec3f normVec = norm(g_activeCameraState.viewMat * (this->f10_mat10 * Resource->geom_base[vertJ->index] + this->f4_vec4 - g_activeCameraState.v3f));
            Vec3f uvVec1 = this->f10_mat10 * vertJ->vec * 0.5;

            Vec3f v97 = Resource->geom_base[vertJ->index] - v77;

            Color3f col = color;
            v121.accumulatePreBaked(&col, &v97, &vertJ->vec);
            col = col * colorMult;

            Uv2f uv;
            uv.u = uvVec1.z * normVec.x - uvVec1.x * normVec.z - -0.5;
            uv.v = uvVec1.z * normVec.y - uvVec1.y * normVec.z - -0.5;
            g_Vertex_setColorUv(tri.j, &col, &uv);
        }
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) {
            Vec3f normVec = norm(g_activeCameraState.viewMat * (this->f10_mat10 * Resource->geom_base[vertK->index] + this->f4_vec4 - g_activeCameraState.v3f));
            Vec3f uvVec1 = this->f10_mat10 * vertK->vec * 0.5;

            Vec3f v111 = Resource->geom_base[vertK->index] - v77;

            Color3f col = color;
            v121.accumulatePreBaked(&col, &v111, &vertK->vec);
            col = col * colorMult;

            Uv2f uv;
            uv.u = uvVec1.z * normVec.x - uvVec1.x * normVec.z - -0.5;
            uv.v = uvVec1.z * normVec.y - uvVec1.y * normVec.z - -0.5;
            g_Vertex_setColorUv(tri.k, &col, &uv);
        }
    }
    applyIndxs_sub_58AC20();
    this->f34_pMyMeshResourceHolder->markUsed();
}

void dk2::CEngineDynamicMesh::_addRenderObj_ge2000(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.DynamicMesh_ge2000::disable");
    if (disable) return;

    CPolyMeshResource *Resource = (CPolyMeshResource *) MyMeshResourceHolder_getResource(this->f34_pMyMeshResourceHolder);
    Obj599A8D *v10 = this->f58_pObj571B47->pObj599A8D_x12[this->f70_obj58EC70.arrA[a2]];

    Vec3f v19s = this->f10_mat10 * Resource->pos + this->f4_vec4;
    Vec3f v12 = v19s - v10->vec8;
    long double v15 = sqrt(v12.x * v12.x + v12.y * v12.y) * 3.1415927;
    SceneObject2E_addRenderObj(
            a3,
            &v10->vec8,
            v15 * 0.25 * 1.5 / 2.5, v10->_one,
            &v19s,
            Resource->scale * this->field_54,
            &this->f70_obj58EC70
    );
    this->f34_pMyMeshResourceHolder->markUsed();
}


