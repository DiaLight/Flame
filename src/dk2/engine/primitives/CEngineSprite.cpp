//
// Created by DiaLight on 7/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngineSprite.h"
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

    inline void l_RenderData_addXyScaled(uint32_t idx, const Vec3f &vec) {
        g_RenderData_addXyScaled(idx, (Vec3f *) &vec);
    }

}

void dk2::CEngineSprite::_addRenderObj(int _484, SceneObject2E *a1) {
    static VisualBool disable("CEngine.Sprite::disable");
    if(disable) return;

    __renderFun_setSceneObject2E(a1, 1, 0, 0, this->f3C__diffusionAlpha, 0);
    Obj571B47 *f4C_pTrgObj_ = this->f4C_pTrgObj;

    LightSplatBuffer v25;
//    objarr_init(v25.items, sizeof(LightSplatBuffer_item), 24, (int (__thiscall *)(int)) ret_this_0args);
    v25.count = 0;
    v25.constructor(f4C_pTrgObj_, -1);
    Color3f color = this->color34;
    v25.accumulatePointLight(&color, this->fl);

    Vec3f v4;
    this->fl->substractAssign(&v4, &g_activeCameraState.v3f);

    Vec3f v12 = g_activeCameraState.viewMat * v4;

    float halfWidth = this->f4__swid * 0.5;
    float halfHeiht = this->f8__shei * 0.5;

    Vec3f topLeft {this->f10__endx - halfWidth, this->f14__endy - halfHeiht, 0};
    Vec3f botLeft {this->f10__endx + halfWidth, this->f14__endy - halfHeiht, 0};
    Vec3f botRight {this->f10__endx + halfWidth, this->f14__endy + halfHeiht, 0};
    Vec3f topRight {this->f10__endx - halfWidth, this->f14__endy + halfHeiht, 0};

    if (this->fC__angle) {
        Mat3x3f rotMat;
        rotMat.init_rotationMat(2, this->fC__angle);

        topLeft = rotMat * topLeft;
        botLeft = rotMat * botLeft;
        botRight = rotMat * botRight;
        topRight = rotMat * topRight;
    }

    l_RenderData_addXyScaled(0, v12 + topLeft);
    l_RenderData_addXyScaled(1, v12 + botLeft);
    l_RenderData_addXyScaled(2, v12 + botRight);
    l_RenderData_addXyScaled(3, v12 + topRight);

    g_RenderData_apply(0, 1, 2);
    g_RenderData_apply(0, 2, 3);

    Uv2f topLeftUv {0, 0};
    Uv2f botLeftUv {1, 0};
    Uv2f botRightUv {1, 1};
    Uv2f topRightUv {0, 1};

    if ((g_vertexFlags[0] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(0, &color, &topLeftUv);
    if ((g_vertexFlags[1] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(1, &color, &botLeftUv);
    if ((g_vertexFlags[2] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(2, &color, &botRightUv);
    if ((g_vertexFlags[3] & Vertex_unvisitedColorUv) != 0) g_Vertex_setColorUv(3, &color, &topRightUv);

    applyIndxs_sub_58AC20();
}

