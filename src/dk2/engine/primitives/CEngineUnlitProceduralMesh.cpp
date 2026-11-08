//
// Created by DiaLight on 7/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/CEngineUnlitProceduralMesh.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/utils/Uv2f.h"
#include "tools/visual_debug.h"
#include "dk2/math/color.h"
#include "dk2/ProceduralMeshVertex.h"
#include "dk2/ProceduralMeshIndex.h"
#include "dk2/utils/Idx3us.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "patches/opengl/visual_value.h"


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

}


void dk2::CEngineUnlitProceduralMesh::_addRenderObj(int a2, SceneObject2E *a1) {
    static VisualBool disable("CEngine.UnlitProceduralMesh::disable");
    if(disable) return;

    __renderFun_setSceneObject2E(a1, 1, NULL, NULL, 1.0, 0);
    int limit = (a2 * 256) + 256;
    if (limit > this->f8_triangleCount) limit = this->f8_triangleCount;
    for (int cur = a2 * 256; cur < limit; ++cur) {
        Idx3us &flagsTri = ((Idx3us *) this->f18_part5_flagsIndexesBuf_6)[cur];
        Idx3us &tri = *(Idx3us *) &this->f24_part3_vertexIndexesBuf_8[cur];

        if ((this->f54_flags54 & 0x1000) != 0) {
            if (!g_vertexFlags[flagsTri.i]) g_RenderData_addXyScaled(flagsTri.i, &this->locs14[this->f20_uvsColorsVecs_1C[tri.i].vecIdx]);
            if (!g_vertexFlags[flagsTri.j]) g_RenderData_addXyScaled(flagsTri.j, &this->locs14[this->f20_uvsColorsVecs_1C[tri.j].vecIdx]);
            if (!g_vertexFlags[flagsTri.k]) g_RenderData_addXyScaled(flagsTri.k, &this->locs14[this->f20_uvsColorsVecs_1C[tri.k].vecIdx]);
        } else {
            if (!g_vertexFlags[flagsTri.i]) g_RenderData_addViewProj(flagsTri.i, &this->locs14[this->f20_uvsColorsVecs_1C[tri.i].vecIdx]);
            if (!g_vertexFlags[flagsTri.j]) g_RenderData_addViewProj(flagsTri.j, &this->locs14[this->f20_uvsColorsVecs_1C[tri.j].vecIdx]);
            if (!g_vertexFlags[flagsTri.k]) g_RenderData_addViewProj(flagsTri.k, &this->locs14[this->f20_uvsColorsVecs_1C[tri.k].vecIdx]);
        }
        g_RenderData_apply(flagsTri.i, flagsTri.j, flagsTri.k);
        if ((g_vertexFlags[flagsTri.i] & Vertex_unvisitedColorUv) != 0) {
            ProceduralMeshVertex &vertex = this->f20_uvsColorsVecs_1C[tri.i];
            Uv2f uv = vertex.uv;
            Color3f color = vertex.color * 255.0;
            g_Vertex_setColorUv(flagsTri.i, &color, &uv);
        }
        if ((g_vertexFlags[flagsTri.j] & Vertex_unvisitedColorUv) != 0) {
            ProceduralMeshVertex &vertex = this->f20_uvsColorsVecs_1C[tri.j];
            Uv2f uv = vertex.uv;
            Color3f color = vertex.color * 255.0;
            g_Vertex_setColorUv(flagsTri.j, &color, &uv);
        }
        if ((g_vertexFlags[flagsTri.k] & Vertex_unvisitedColorUv) != 0) {
            ProceduralMeshVertex &vertex = this->f20_uvsColorsVecs_1C[tri.k];
            Uv2f uv = vertex.uv;
            Color3f color = vertex.color * 255.0;
            g_Vertex_setColorUv(flagsTri.k, &color, &uv);
        }
    }
    applyIndxs_sub_58AC20();
}
