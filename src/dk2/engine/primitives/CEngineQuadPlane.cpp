//
// Created by DiaLight on 7/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngineQuadPlane.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/primitive/resource/CAnimMeshResource.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/utils/Uv2f.h"
#include "tools/visual_debug.h"
#include "dk2/LightSplatBuffer.h"
#include "dk2/math/vec.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "patches/opengl/visual_value.h"


namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15);

    inline void l_RenderData_addViewProj(uint32_t idx, const Vec3f &vec) {
        g_RenderData_addViewProj(idx, (Vec3f *) &vec);
    }

}

void dk2::CEngineQuadPlane::_addRenderObj(int _498, SceneObject2E *a1) {
    static VisualBool disable("CEngine.QuadPlane::disable");
    if (disable) return;

    __renderFun_setSceneObject2E(a1, 1, 0, 0, this->f2C__diffusionAlpha, 0);

    Color3f color = this->f18_color18;

    LightSplatBuffer v23;
//    objarr_init(v23.items, 0x28, 24, (int (__thiscall *)(int)) ret_this_0args);
    v23.count = 0;
    v23.constructor(this->f34_pObj571B47, -1);
    v23.accumulatePointLight(&color, &this->field_C);

    Vec3f topLeft{-this->f4_xyScale, -this->f4_xyScale, 0.0};
    Vec3f botLeft{this->f4_xyScale, -this->f4_xyScale, 0.0};
    Vec3f botRight{this->f4_xyScale, this->f4_xyScale, 0.0};
    Vec3f topRight{-this->f4_xyScale, this->f4_xyScale, 0.0};

    if (this->f8_rotAngle != 0.0) {
        Mat3x3f rotMat;
        rotMat.init_rotationMat(2, this->f8_rotAngle);
        topLeft = rotMat * topLeft;
        botLeft = rotMat * botLeft;
        botRight = rotMat * botRight;
        topRight = rotMat * topRight;
    }

    l_RenderData_addViewProj(0, this->field_C + topLeft);
    l_RenderData_addViewProj(1, this->field_C + botLeft);
    l_RenderData_addViewProj(2, this->field_C + botRight);
    l_RenderData_addViewProj(3, this->field_C + topRight);

    g_RenderData_apply(0, 1, 2);
    g_RenderData_apply(0, 2, 3);

    Uv2f topLeftUv{0, 0};
    Uv2f botLeftUv{1, 0};
    Uv2f botRightUv{1, 1};
    Uv2f topRightUv{0, 1};

    if ((g_vertexFlags[0] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(0, &color, &topLeftUv);
    if ((g_vertexFlags[1] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(1, &color, &botLeftUv);
    if ((g_vertexFlags[2] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(2, &color, &botRightUv);
    if ((g_vertexFlags[3] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(3, &color, &topRightUv);

    applyIndxs_sub_58AC20();
}
