//
// Created by DiaLight on 7/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngine2DStaticMesh.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/primitive/resource/CPolyMeshResource.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MeshVertEx.h"
#include "dk2/SprsMeshHeader.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/utils/Idx3ub.h"
#include "dk2/math/vec.h"
#include "dk2/MyMeshResourceHolder.h"
#include "tools/visual_debug.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "patches/opengl/visual_value.h"

namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

}

void dk2::CEngine2DStaticMesh::_addRenderObj(int a2, SceneObject2E *a3) {
    static VisualBool disable("CEngine.2DStaticMesh::disable");
    if(disable) return;

    CPolyMeshResource *Resource = (CPolyMeshResource *) MyMeshResourceHolder_getResource(this->f4C_resHolder);
    SprsMeshHeader *v4 = &Resource->ptr[a2];
    __renderFun_setSceneObject2E(a3, 0, 0, 0, 1.0, 0);
    Vec3f scale {this->f34_scale, this->f34_scale, this->f38_scaleZ};
    for (int i = 0; i < v4->triangleCount_list[0]; ++i) {
        Idx3ub tri = v4->pvertice_list[0][i];

        MeshVertEx *vertI = &v4->MeshVertEx_base[tri.i];
        MeshVertEx *vertJ = &v4->MeshVertEx_base[tri.j];
        MeshVertEx *vertK = &v4->MeshVertEx_base[tri.k];

        if (!g_vertexFlags[tri.i]) {
            Vec3f vec = (this->f10_mat * Resource->geom_base[vertI->index]) * scale + this->f4_vec4;
            g_RenderData_addZCapped(tri.i, &vec);
        }
        if (!g_vertexFlags[tri.j]) {
            Vec3f vec = (this->f10_mat * Resource->geom_base[vertJ->index]) * scale + this->f4_vec4;
            g_RenderData_addZCapped(tri.j, &vec);
        }
        if (!g_vertexFlags[tri.k]) {
            Vec3f vec = (this->f10_mat * Resource->geom_base[vertK->index]) * scale + this->f4_vec4;
            g_RenderData_addZCapped(tri.k, &vec);
        }
        g_RenderData_apply(tri.i, tri.j, tri.k);

        Uv2f uvI = UQ15_to_Uv2f(vertI->uv);
        Uv2f uvJ = UQ15_to_Uv2f(vertJ->uv);
        Uv2f uvK = UQ15_to_Uv2f(vertK->uv);

        if ((g_vertexFlags[tri.i] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.i, &this->f40_color, &uvI);
        if ((g_vertexFlags[tri.j] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.j, &this->f40_color, &uvJ);
        if ((g_vertexFlags[tri.k] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(tri.k, &this->f40_color, &uvK);
    }
    applyIndxs_sub_58AC20();
    this->f4C_resHolder->markUsed();
}
