//
// Created by DiaLight on 7/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngineVirtualPerspective2DAnimMesh.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/primitive/resource/CAnimMeshResource.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/MyMeshResourceHolder.h"
#include "dk2/utils/Idx3ub.h"
#include "tools/visual_debug.h"
#include "dk2/SprsAnimHeader.h"
#include "dk2/AnimVertEx.h"
#include "dk2/math/vec.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "patches/opengl/visual_value.h"


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

}

void dk2::CEngineVirtualPerspective2DAnimMesh::_addRenderObj(
        int a2,
        SceneObject2E *a3) {
    static VisualBool disable("CEngine.VirtualPerspective2DAnimMesh::disable");
    if(disable) return;

    CAnimMeshResource *pResource = (CAnimMeshResource *) MyMeshResourceHolder_getResource(this->f54_resHolder);
    SprsAnimHeader *pHeader = &pResource->buf[a2];
    __renderFun_setSceneObject2E(a3, 0, 0, 0, 1.0, 0);
    double v6 = this->field_44;
    if (v6 < 0.0) v6 = 0.0;
    bool v8 = v6 < 1.0;
    bool v9 = v6 == 1.0;
    if ((pResource->frameFactorFunction & 1) != 0) {
        if (!v8 && !v9) {
            do
                v6 = v6 - 1.0;
            while (v6 > 1.0);
        }
    } else if (!v8 && !v9) {
        v6 = 1.0;
    }
    int f8_frameCount = pResource->frameCount;
    float v27 = (double) (f8_frameCount - 1) * v6;
    int v11 = strangeOptimizedMultiplyAddCast(v27, 1, 0);

    int v26 = v11;
    if (v11 < 0) {
        v26 = 0;
        v11 = 0;
    }
    if (v11 > f8_frameCount - 2)
        v26 = f8_frameCount - 2;

    for (int i = 0; i < pHeader->lod_list[0]; ++i) {
        Idx3ub tri = pHeader->plod_list[0][i];

        AnimVertEx *vertI = &pHeader->AnimVertEx_base[tri.i];
        AnimVertEx *vertJ = &pHeader->AnimVertEx_base[tri.j];
        AnimVertEx *vertK = &pHeader->AnimVertEx_base[tri.k];

        Vec3f scale{this->f38_xyScale, this->f38_xyScale, this->f3C_zScale};
        Vec3f translate{(float) this->f4_xTranslate, (float) this->f8_yTranslate, this->fC_zTranslate};
        if (!g_vertexFlags[tri.i]) {
            Vec3f a3a;
            pResource->sub_57E5B0(a2, v27, v26, tri.i, &a3a);
            Vec3f vec = this->f14_mat14 * a3a;
            float zMul = 1.f / (this->f10_negZ + vec.z);
            vec = vec * Vec3f {zMul, zMul, 1} * scale + translate;
            g_RenderData_addZCapped(tri.i, &vec);
        }
        if (!g_vertexFlags[tri.j]) {
            Vec3f a3a;
            pResource->sub_57E5B0(a2, v27, v26, tri.j, &a3a);
            Vec3f vec = this->f14_mat14 * a3a;
            float zMul = 1.f / (this->f10_negZ + vec.z);
            vec = vec * Vec3f {zMul, zMul, 1} * scale + translate;
            g_RenderData_addZCapped(tri.j, &vec);
        }
        if (!g_vertexFlags[tri.k]) {
            Vec3f a3a;
            pResource->sub_57E5B0(a2, v27, v26, tri.k, &a3a);
            Vec3f vec = this->f14_mat14 * a3a;
            float zMul = 1.f / (this->f10_negZ + vec.z);
            vec = vec * Vec3f {zMul, zMul, 1} * scale + translate;
            g_RenderData_addZCapped(tri.k, &vec);
        }
        g_RenderData_apply(tri.i, tri.j, tri.k);

        Uv2f uvX = UQ15_to_Uv2f(vertI->uv);
        Uv2f uvY = UQ15_to_Uv2f(vertJ->uv);
        Uv2f uvZ = UQ15_to_Uv2f(vertK->uv);

        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.i, &this->f48_color, &uvX);
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.j, &this->f48_color, &uvY);
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.k, &this->f48_color, &uvZ);
    }
    applyIndxs_sub_58AC20();
    this->f54_resHolder->markUsed();
}


