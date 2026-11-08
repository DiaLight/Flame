//
// Created by DiaLight on 6/29/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/SceneObject2E.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/utils/Uv2f_arr1024.h"
#include "dk2/MyD3D3Vertex.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/AtlasMeshGroup.h"
#include "dk2/Triangle24.h"
#include "dk2/math/vec.h"
#include "dk2/math/mat.h"
#include "dk2/math/q12_utils.h"
#include "dk2/utils/Idx3us.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"
#include "Vertex_flags.h"
#include "RenderState_flags.h"
#include "patches/opengl/visual_value.h"
#include <cmath>


void __cdecl dk2::MyCameraState_computeProjectionMat(MyCameraState *pState) {
    g_cachedCameraState = *pState;

    g_cachedCameraState.flags ^= (LOBYTE(g_cachedCameraState.flags) ^ (uint8_t)(pState->flags << 31 >> 31)) & 1;
    g_cachedCameraState.flags ^= (LOBYTE(g_cachedCameraState.flags) ^ (uint8_t)(pState->flags << 30 >> 30)) & 2;
    g_cachedCameraState.flags ^= (LOBYTE(g_cachedCameraState.flags) ^ (uint8_t)(pState->flags << 29 >> 29)) & 4;
    g_cachedCameraState.flags ^= (LOBYTE(g_cachedCameraState.flags) ^ (uint8_t)(pState->flags << 28 >> 28)) & 8;

    g_viewWidth = g_cachedCameraState.trg.x - g_cachedCameraState.leftRight.x;
    g_viewHeight = g_cachedCameraState.trg.y - g_cachedCameraState.topBottom.x;
    g_viewLeft = g_cachedCameraState.trg.x - -0.25;
    g_viewBottom = g_cachedCameraState.trg.y - -0.25;

    g_RenderData_Xscale = g_cachedCameraState.ww240_viewRange / g_viewWidth;
    g_RenderData_Yscale = g_cachedCameraState.ww240_viewRange / g_viewHeight;

    g_farPlane = pState->farPlane;
    g_2divFarPlane = 2.f / pState->farPlane;

    Mat3x3f projectionMat {.m={
            {g_RenderData_Xscale, 0.f, 0.f},
            {0.f, g_RenderData_Yscale, 0.f},
            {0.f, 0.f, 1.f},  // Identity z-component
    }};

    if(!patch::opengl_patch::ignoreCameraMatrix[5]) {
        g_baseViewProj = g_cachedCameraState.viewMat * projectionMat;
    } else {
        g_baseViewProj = Mat3x3f {.m={
                {1.f, 0.f, 0.f},
                {0.f, 1.f, 0.f},
                {0.f, 0.f, 1.f},
        }};
    }

    Vec3f tmpVec2;
    if(!patch::opengl_patch::ignoreCameraMatrix[6]) {
        tmpVec2 = g_baseViewProj * (-g_cachedCameraState.v3f);
    } else {
        tmpVec2 = Vec3f {0, 0, 0};
    }

    g_viewTransformOffset = tmpVec2;
    g_viewTransformTranslation = tmpVec2;
    g_viewProjBackup = g_baseViewProj;
    g_RenderData_matViewProj = g_baseViewProj;
    g_isCameraProjView = 1;
}


void __cdecl dk2::Vertex_setColorUv_Hardware_m0(uint32_t vertIndex, Color3f *cols, Uv2f *uvs) {
    if ((g_vertexFlags[vertIndex] & Vertex_registeredM0) == 0) {
        return Vertex_setColorUv_Hardware_m1(vertIndex, cols, uvs);
    }
    for (int i = 0; i < g_pSceneObject2E->texStagesCount; ++i) {
        g_Color3f_arr2x1024[i].arr[vertIndex].r = cols[i].r;
        g_Color3f_arr2x1024[i].arr[vertIndex].g = cols[i].g;
        g_Color3f_arr2x1024[i].arr[vertIndex].b = cols[i].b;
    }
    for (int i = 0; i < g_pSceneObject2E->surfhCount; ++i) {
        g_Uv2f_arr4x1024[i].arr[vertIndex].u = uvs[i].u;
        g_Uv2f_arr4x1024[i].arr[vertIndex].v = uvs[i].v;
    }
    uint8_t flags = g_vertexFlags[vertIndex];
    if ((flags & Vertex_registeredM1) != 0) {
        return Vertex_setColorUv_Hardware_m1(vertIndex, cols, uvs);
    }
    g_vertexFlags[vertIndex] = flags & ~Vertex_unvisitedColorUv;
}


void __cdecl dk2::Vertex_setColorUv_Hardware_m1(uint32_t vertIndex, Color3f *cols, Uv2f *uvs) {
    g_vertexFlags[vertIndex] &= ~Vertex_unvisitedColorUv;
    RenderData *pRenderData = &g_RenderData_instance_arr[vertIndex];

    uint8_t vertFlags = g_vertexFlags[vertIndex];
    int uvCounter = 0;
    for (int stage = 0; stage < g_pSceneObject2E->texStagesCount; ++stage) {
        VerticesData &verticesData = g_vertices[stage];
        MyD3D3Vertex *pVert = (MyD3D3Vertex *) ((char *) verticesData.MyD3D3Vertex_pos + pRenderData->vtxIdx * g_MyD3D3Vertex_size);
        pVert->vec = pRenderData->vecC;
        pVert->oneDivZ = pRenderData->oneDivZ;

        {  // calc diffuse color
            Color3f &pCol3F = cols[stage];

            int32_t u32R = strangeOptimizedMultiplyAddCast(pCol3F.r, 1, 0);
            int32_t u32G = strangeOptimizedMultiplyAddCast(pCol3F.g, 1, 0);
            int32_t u32B = strangeOptimizedMultiplyAddCast(pCol3F.b, 1, 0);

            if (vertFlags & Vertex_hasBrightness) {
                int brightnessFl16 = pRenderData->_brightness_fl16;
                u32R = (brightnessFl16 * u32R) >> 16;
                u32G = (brightnessFl16 * u32G) >> 16;
                u32B = (brightnessFl16 * u32B) >> 16;
            }
            if (u32R > 255) u32R = 255;
            if (u32G > 255) u32G = 255;
            if (u32B > 255) u32B = 255;

            if(!patch::opengl_patch::enabled) {  // DirectX 7 uses BGRA color format
                int diffuseColor = g_diffuseAlpha_shl24 + ((((u32R << 8) + u32G) << 8) + u32B);
                pVert->diffuse = diffuseColor;
            } else {  // OpenGL uses RGBA color format
                int diffuseColor = g_diffuseAlpha_shl24 + ((((u32B << 8) + u32G) << 8) + u32R);
                pVert->diffuse = diffuseColor;
            }
        }
        {  // patch (check for buf used)
            if(verticesData.MyD3D3Vertex_pos != verticesData.MyD3D3Vertices) {
                MyD3D3Vertex *p1 = (MyD3D3Vertex *) ((char *) g_MyD3D3Vertex_buf + g_totalVerticesCount * g_MyD3D3Vertex_size);
                if(verticesData.MyD3D3Vertex_pos != p1) {
                    GetTickCount();
                }
            }
        }

        {  // calc uv for each sample
            uint8_t uvCount = g_pSceneObject2E->numTextureSamplers_x2[stage];

            if(!uvCount) uvCount = 1;
            {  // patch
                if(uvCount > MyDirectDraw_instance_triangles.texturesCount) {
                    throw std::exception("g_MyD3D3Vertex_size overflow");
                    uvCount = MyDirectDraw_instance_triangles.texturesCount;
                }
            }
            for (int i = 0; i < uvCount; ++i) {
                pVert->tex[i].u = g_texUMul[uvCounter] * uvs[uvCounter].u + g_texUAdd[uvCounter];
                pVert->tex[i].v = g_texVMul[uvCounter] * uvs[uvCounter].v + g_texVAdd[uvCounter];
                uvCounter++;
            }
        }
    }
}

void __cdecl dk2::setupDepthCoefficients(
        int clipMode,
        float camNear,
        float camFar,
        float clipZMin,
        float clipZMax,
        int enablePerspective) {
    g_currentDepthMode = -1;

    float clipSize = clipZMax - clipZMin;
    float camSize = camFar - camNear;

    float depthTriSlope = clipSize * 1024.f / camSize * 0.33333334f;
    g_depthTriMulArr[clipMode] = depthTriSlope;
    g_depthTriAddArr[clipMode] = clipZMin * 1024.f - depthTriSlope * camNear * 3.f;

    if (!enablePerspective) {
        g_depthLinearMulArr[clipMode] = clipSize / camSize;
        g_depthLinearAddArr[clipMode] = clipZMin - camNear * (clipSize / camSize);
        return;
    }
    if (camNear <= 0.5) {
        float depthContinuityFactor = camFar * 0.5f / (camFar + camFar - 0.5f);
        g_depthLinearAddArr[clipMode] = clipZMin;
        g_depthLinearMulArr[clipMode] = depthContinuityFactor / (0.5f * 0.5f) * clipSize;

        g_depthPerspMulArr[clipMode] = depthContinuityFactor * clipSize;
        g_depthPerspAddArr[clipMode] = (depthContinuityFactor / camFar - -1.f) * clipSize + clipZMin;
    } else {
        float invCamFar = 1.f / camFar;
        g_depthPerspMulArr[clipMode] = clipSize / (1.f / camNear - invCamFar);
        g_depthPerspAddArr[clipMode] = clipSize / (1.f / camNear - invCamFar) / camNear + clipZMin;
    }
}

void __cdecl dk2::__renderFun_setSceneObject2E(
        SceneObject2E *pObj2E,
        int a2,
        Mat3x3f *a3_mat,
        Vec3f *a4_vec,
        float a5_diffuseAlpha,
        int a6_m) {
    for (int i = 0; i < pObj2E->surfhCount; ++i) {
        MyCESurfHandle *reduction = pObj2E->surfh_x4[i]->curReduction;
        g_texUMul[i] = reduction->texUMul;
        g_texVMul[i] = reduction->texVMul;
        g_texUAdd[i] = reduction->texUAdd;
        g_texVAdd[i] = reduction->texVAdd;
    }
    g_pSceneObject2E = pObj2E;
    if (g_currentDepthMode != pObj2E->currentDepthMode) {
        g_currentDepthMode = pObj2E->currentDepthMode;
        int mode = pObj2E->currentDepthMode;
        g_depthTriMul = g_depthTriMulArr[mode];
        g_depthTriAdd = g_depthTriAddArr[mode];
        g_depthLinearMul = g_depthLinearMulArr[mode];
        g_depthLinearAdd = g_depthLinearAddArr[mode];
        g_depthPerspMul = g_depthPerspMulArr[mode];
        g_depthPerspAdd = g_depthPerspAddArr[mode];
    }
    g_renderFun_arg2 = a2;

    {  // configure alpha channel
        int32_t value = strangeOptimizedMultiplyAddCast(a5_diffuseAlpha, 255.f, 0);
        if (value < 0) value = 0;
        if (value > 255) value = 255;
        g_diffuseAlpha_shl24 = value << 24;
    }
    g_RenderData_arr_count = pObj2E->numVertsEx;

    if (a3_mat) {
        g_RenderData_matViewProj = *a3_mat * g_baseViewProj;
        g_viewTransformTranslation = g_baseViewProj * (*a4_vec - g_cachedCameraState.v3f);
        g_isCameraProjView = 0;
    } else if (!g_isCameraProjView) {
        g_viewTransformTranslation = g_viewTransformOffset;
        g_RenderData_matViewProj = g_viewProjBackup;
        g_isCameraProjView = 1;
    }
    g_RenderData_addXyScaled = RenderData_addXyScaled;
    if (a6_m) {
        g_RenderData_addViewProj = RenderData_addViewProj_m1;
        g_RenderData_addZCapped = RenderData_addZCapped;
        g_RenderData_apply = RenderData_apply_m1;
        if ((MyDirectDraw_instance_uvs.flags & 1) != 0) {
            g_Vertex_setColorUv = Vertex_setColorUv_Software3D_MMX_m1;
        } else {
            g_Vertex_setColorUv = Vertex_setColorUv_Hardware_m1;
        }
    } else {
        g_RenderData_addViewProj = RenderData_addViewProj_m0;
        g_RenderData_addZCapped = RenderData_addZCapped;
        g_RenderData_apply = RenderData_apply_m0;
        if ((MyDirectDraw_instance_uvs.flags & 1) != 0) {
            g_Vertex_setColorUv = Vertex_setColorUv_Software3D_MMX_m0;
        } else {
            g_Vertex_setColorUv = Vertex_setColorUv_Hardware_m0;
        }
    }
}

void dk2::applyIndxs_sub_58AC20() {
    if (g_renderFun_arg2) {
        for (int i = 0; i < g_ItersectView_Idx3b_arr_count; ++i) {
            adjustAndAddToRender_sub_58BB60(&g_ItersectView_Idx3b_arr_instance[i]);
        }
    } else {
        for (int i = 0; i < g_ItersectView_Idx3b_arr_count; ++i) {
            adjustAndAddToRender_sub_58CC40(&g_ItersectView_Idx3b_arr_instance[i]);
        }
    }
    memset(g_vertexFlags, 0, g_RenderData_arr_count);
    for (int i = 0; i < g_RenderData_arr_count; ++i) {
        g_RenderData_instance_arr[i].vtxIdx = -1;
    }
    g_ItersectView_Idx3b_arr_count = 0;
}

void __cdecl dk2::RenderData_addXyScaled(uint32_t a1_idx, Vec3f *vec) {
    Vec3f res;
    if(!patch::opengl_patch::ignoreCameraMatrix[0]) {
        res = *vec * Vec3f{g_RenderData_Xscale, g_RenderData_Yscale, 1.f};
    } else {
        res = *vec;
    }
    RenderData_addToArr_m0(a1_idx, &res);
}

void __cdecl dk2::RenderData_addViewProj_m0(uint32_t a1_idx, Vec3f *vec) {
    Vec3f res;
    if(!patch::opengl_patch::ignoreCameraMatrix[1]) {
        res = (g_RenderData_matViewProj * *vec) + g_viewTransformTranslation;
    } else {
        res = *vec;
    }
    RenderData_addToArr_m0(a1_idx, &res);
}

void __cdecl dk2::RenderData_addViewProj_m1(uint32_t a1_idx, Vec3f *vec) {
    Vec3f res;
    if(!patch::opengl_patch::ignoreCameraMatrix[2]) {
        res = (g_RenderData_matViewProj * *vec) + g_viewTransformTranslation;
    } else {
        res = *vec;
    }
    RenderData_addToArr_m1(a1_idx, &res);
}

#define DK2_magicSemiOne 0.99993896  // = 1.0 - (1.0 / 0x3FFF)
#define DK2_magicSemiZero 0.000061035156  // = 1.0 / 0x4000

void __cdecl dk2::RenderData_addZCapped(unsigned int a1, Vec3f *a2) {
    // calc view frustum culling
    float f8_z = a2->z;
    if (f8_z < DK2_magicSemiZero) f8_z = DK2_magicSemiZero;
    if (f8_z > 1.0) f8_z = 1.0;

    float v4_z;
    if(!patch::opengl_patch::ignoreCameraMatrix[4]) {
        v4_z = g_depthLinearMul * f8_z + g_depthLinearAdd;
    } else {
        v4_z = f8_z;
    }

    g_RenderData_instance_arr[a1].oneDivZ = 1.0;
    g_RenderData_instance_arr[a1].vec0 = Vec3f {a2->x, a2->y, f8_z };
    g_RenderData_instance_arr[a1].vecC = Vec3f {a2->x, a2->y, v4_z };

    float x_sub_left = a2->x - g_left_77F3F4;
    float right_sub_x = g_right_77F4EC - a2->x;
    float y_sub_top = a2->y - g_top_780938;
    float bot_sub_y = g_bottom_77937C - a2->y;

    int frustumFlags =
            (8 * ((*(uint32_t *) &right_sub_x) >> 31)) |
            (4 * ((*(uint32_t *) &x_sub_left) >> 31)) |
            (2 * ((*(uint32_t *) &bot_sub_y) >> 31)) |
            (1 * ((*(uint32_t *) &y_sub_top) >> 31));


    static VisualBool disableSoftwareFrustumCulling("disableSoftwareFrustumCulling zCapped");
    if(disableSoftwareFrustumCulling) {
        frustumFlags = 0;
    }

    g_RenderData_instance_arr[a1].frustumFlags = frustumFlags;
}

dk2::Vec3f *dk2::Mat3x3f::multiplyVec(Vec3f *retstr, Vec3f *inVec) {
    return *retstr = Vec3f {
            this->m[0][0] * inVec->x + this->m[1][0] * inVec->y + this->m[2][0] * inVec->z,
            this->m[0][1] * inVec->x + this->m[1][1] * inVec->y + this->m[2][1] * inVec->z,
            this->m[0][2] * inVec->x + this->m[1][2] * inVec->y + this->m[2][2] * inVec->z,
    }, retstr;
}

dk2::Vec3f *dk2::Mat3x3f::multiplyVec_0(Vec3f *inVec, Vec3f *retstr) {
    return *retstr = Vec3f {
            this->m[0][0] * inVec->x + this->m[1][0] * inVec->y + this->m[2][0] * inVec->z,
            this->m[0][1] * inVec->x + this->m[1][1] * inVec->y + this->m[2][1] * inVec->z,
            this->m[0][2] * inVec->x + this->m[1][2] * inVec->y + this->m[2][2] * inVec->z,
    }, retstr;
}

dk2::Mat3x3f *dk2::Mat3x3f::multiplyMat(Mat3x3f *out, Mat3x3f *lhs) {
    out->m[0][0] = this->m[0][0] * lhs->m[0][0] + this->m[1][0] * lhs->m[0][1] + this->m[2][0] * lhs->m[0][2];
    out->m[0][1] = this->m[0][1] * lhs->m[0][0] + this->m[1][1] * lhs->m[0][1] + this->m[2][1] * lhs->m[0][2];
    out->m[0][2] = this->m[0][2] * lhs->m[0][0] + this->m[1][2] * lhs->m[0][1] + this->m[2][2] * lhs->m[0][2];
    out->m[1][0] = this->m[0][0] * lhs->m[1][0] + this->m[1][0] * lhs->m[1][1] + this->m[2][0] * lhs->m[1][2];
    out->m[1][1] = this->m[0][1] * lhs->m[1][0] + this->m[1][1] * lhs->m[1][1] + this->m[2][1] * lhs->m[1][2];
    out->m[1][2] = this->m[0][2] * lhs->m[1][0] + this->m[1][2] * lhs->m[1][1] + this->m[2][2] * lhs->m[1][2];
    out->m[2][0] = this->m[0][0] * lhs->m[2][0] + this->m[1][0] * lhs->m[2][1] + this->m[2][0] * lhs->m[2][2];
    out->m[2][1] = this->m[0][1] * lhs->m[2][0] + this->m[1][1] * lhs->m[2][1] + this->m[2][1] * lhs->m[2][2];
    out->m[2][2] = this->m[0][2] * lhs->m[2][0] + this->m[1][2] * lhs->m[2][1] + this->m[2][2] * lhs->m[2][2];
    return out;
}

namespace dk2 {

    inline float calcNormalizedDepth(const Vec3f &vec) {
        // qwen2.6:
        // It converts a raw 3D coordinate into a normalized depth value,
        // while applying a geometric correction that accounts for
        // how depth varies with x and y in non-orthographic or asymmetric projections
        float abs_xy = fabs(vec.x) + fabs(vec.y);
        float result = (g_farPlane - (vec.z - abs_xy * -0.5f)) * g_2divFarPlane;
        return result;
    }

}

void __cdecl dk2::RenderData_addToArr_m0(uint32_t a1_idx, Vec3f *vec) {
    g_vertexFlags[a1_idx] = Vertex_isVisited;
    g_RenderData_instance_arr[a1_idx].vec0 = *vec;

    float z_add_x = vec->z - -vec->x;
    float z_sub_x = vec->z - vec->x;
    float z_add_y = vec->z - -vec->y;
    float z_sub_y = vec->z - vec->y;

    uint32_t frustumFlags =
            (8 * ((*(uint32_t *) &z_sub_x) >> 31)) |
            (4 * ((*(uint32_t *) &z_add_x) >> 31)) |
            (2 * ((*(uint32_t *) &z_sub_y) >> 31)) |
            (1 * ((*(uint32_t *) &z_add_y) >> 31));

    static VisualBool disableSoftwareFrustumCulling("disableSoftwareFrustumCulling m0");
    if(disableSoftwareFrustumCulling) {
        frustumFlags = 0;
    }

    if (frustumFlags != 0) {
        g_RenderData_instance_arr[a1_idx].frustumFlags = frustumFlags;
        return;
    }

    if ((g_cachedCameraState.flags & 8) != 0) {
        float depth = calcNormalizedDepth(*vec);
        if (depth < 0) {
            frustumFlags = 0x20;
            g_vertexFlags[a1_idx] |= Vertex_hasBrightness;
            g_RenderData_instance_arr[a1_idx]._brightness_fl16 = 0;
        } else if (depth < 1.0) {
            g_vertexFlags[a1_idx] |= Vertex_hasBrightness;
            g_RenderData_instance_arr[a1_idx]._brightness_fl16 = strangeOptimizedMultiplyAddCast(depth, 65536.f, 0);
        }
    }

    static VisualBool disableSoftwarePerspective("disableSoftwarePerspective m0");
    if (disableSoftwarePerspective) {
        g_RenderData_instance_arr[a1_idx].vecC = *vec;
    } else {
        g_RenderData_instance_arr[a1_idx].vecC.x = g_viewWidth * vec->x / vec->z + g_viewLeft;
        g_RenderData_instance_arr[a1_idx].vecC.y = g_viewHeight * vec->y / vec->z + g_viewBottom;
        float v9;
        if (vec->z > 0.5) {
            v9 = g_depthPerspAdd - g_depthPerspMul / vec->z;
        } else {
            v9 = g_depthLinearAdd + g_depthLinearMul * vec->z;
        }
        if (v9 > DK2_magicSemiOne) v9 = DK2_magicSemiOne;
        g_RenderData_instance_arr[a1_idx].vecC.z = v9;
    }

    g_RenderData_instance_arr[a1_idx].oneDivZ = 1.f / vec->z;
    g_RenderData_instance_arr[a1_idx].frustumFlags = frustumFlags;
}


void __cdecl dk2::RenderData_addToArr_m1(uint32_t idx, Vec3f *vec) {
    g_vertexFlags[idx] = Vertex_isVisited;
    g_RenderData_instance_arr[idx].vec0 = *vec;

    if ((g_cachedCameraState.flags & 8) != 0) {
        float depth = calcNormalizedDepth(*vec);
        if (depth < 0) {
            g_vertexFlags[idx] |= Vertex_hasBrightness;
            g_RenderData_instance_arr[idx].frustumFlags = 0x20;
            g_RenderData_instance_arr[idx]._brightness_fl16 = 0;
        } else if (depth < 1.0) {
            g_vertexFlags[idx] |= Vertex_hasBrightness;
            g_RenderData_instance_arr[idx]._brightness_fl16 = strangeOptimizedMultiplyAddCast(depth, 65536.f, 0);
        }
    }

    static VisualBool disableSoftwarePerspective("disableSoftwarePerspective m1");
    if (disableSoftwarePerspective) {
        g_RenderData_instance_arr[idx].vecC = *vec;
    } else {
        g_RenderData_instance_arr[idx].vecC.x = g_viewWidth * vec->x / vec->z + g_viewLeft;
        g_RenderData_instance_arr[idx].vecC.y = g_viewHeight * vec->y / vec->z + g_viewBottom;
        float v9;
        if (vec->z > 0.5) {
            v9 = g_depthPerspAdd - g_depthPerspMul / vec->z;
        } else {
            v9 = g_depthLinearAdd + g_depthLinearMul * vec->z;
        }
        if (v9 > DK2_magicSemiOne) v9 = DK2_magicSemiOne;  // = 1.0 - (1.0 / 0x3FFF)
        g_RenderData_instance_arr[idx].vecC.z = v9;
    }

    g_RenderData_instance_arr[idx].oneDivZ = 1.f / vec->z;
    g_RenderData_instance_arr[idx].frustumFlags = 0;
}

void __cdecl dk2::RenderData_apply_m0(unsigned int idxX, unsigned int idxY, unsigned int idxZ) {
    int xFfl = g_RenderData_instance_arr[idxX].frustumFlags;
    int yFfl = g_RenderData_instance_arr[idxY].frustumFlags;
    int zFfl = g_RenderData_instance_arr[idxZ].frustumFlags;
    if ((xFfl & zFfl & yFfl) != 0) return;  // complete outside view
    if ((yFfl | xFfl | zFfl) != 0) {  // intersect view border
        g_vertexFlags[idxX] |= Vertex_registeredM0 | Vertex_unvisitedColorUv;
        g_vertexFlags[idxY] |= Vertex_registeredM0 | Vertex_unvisitedColorUv;
        g_vertexFlags[idxZ] |= Vertex_registeredM0 | Vertex_unvisitedColorUv;
        int idx = g_ItersectView_Idx3b_arr_count;
        g_ItersectView_Idx3b_arr_instance[idx].i = idxX;
        g_ItersectView_Idx3b_arr_instance[idx].j = idxY;
        g_ItersectView_Idx3b_arr_instance[idx].k = idxZ;
        g_ItersectView_Idx3b_arr_count = idx + 1;
    } else {
        // inside view
        RenderData_apply_m1(idxX, idxY, idxZ);
    }
}

void __cdecl dk2::RenderData_apply_m1(unsigned int vert1, unsigned int vert2, unsigned int vert3) {
    RenderData *pVert1Rd = &g_RenderData_instance_arr[vert1];
    RenderData *pVert2Rd = &g_RenderData_instance_arr[vert2];
    RenderData *pVert3Rd = &g_RenderData_instance_arr[vert3];

    if ((pVert1Rd->frustumFlags & pVert2Rd->frustumFlags & pVert3Rd->frustumFlags) != 0) return;  // outside scene

    // ignore triangle facing out camera
    if ((pVert2Rd->vecC.x - pVert1Rd->vecC.x) * (pVert3Rd->vecC.y - pVert1Rd->vecC.y)
        - (pVert2Rd->vecC.y - pVert1Rd->vecC.y) * (pVert3Rd->vecC.x - pVert1Rd->vecC.x) < 0.0) return;  // 2D cross product of two vectors in a triangle's plane. negative means clockwise

    if (pVert1Rd->vtxIdx < 0) {
        pVert1Rd->vtxIdx = g_DrawTriangleList_verticesCount++;
        g_vertexFlags[vert1] |= Vertex_registeredM1 | Vertex_unvisitedColorUv;
    }
    if (pVert2Rd->vtxIdx < 0) {
        pVert2Rd->vtxIdx = g_DrawTriangleList_verticesCount++;
        g_vertexFlags[vert2] |= Vertex_registeredM1 | Vertex_unvisitedColorUv;
    }
    if (pVert3Rd->vtxIdx < 0) {
        pVert3Rd->vtxIdx = g_DrawTriangleList_verticesCount++;
        g_vertexFlags[vert3] |= Vertex_registeredM1 | Vertex_unvisitedColorUv;
    }
    if ((g_pSceneObject2E->renderFlags_x2[0] & RenderState_use3DPipeline) != 0) {
        int32_t res;
        if(!patch::opengl_patch::ignoreCameraMatrix[3]) {
            res = strangeOptimizedMultiplyAddCast(
                    pVert2Rd->vec0.z + pVert1Rd->vec0.z + pVert3Rd->vec0.z,
                    g_depthTriMul, g_depthTriAdd);
        } else {
            res = pVert2Rd->vec0.z + pVert1Rd->vec0.z + pVert3Rd->vec0.z;
        }
        MyEntryBuf_Triangle24_add(
                pVert1Rd->vtxIdx,
                pVert2Rd->vtxIdx,
                pVert3Rd->vtxIdx,
                res);
    } else {
        g_CEnginePrimitiveBase_addObj_lpwIndices->i = pVert1Rd->vtxIdx;
        g_CEnginePrimitiveBase_addObj_lpwIndices->j = pVert2Rd->vtxIdx;
        g_CEnginePrimitiveBase_addObj_lpwIndices->k = pVert3Rd->vtxIdx;
        ++g_CEnginePrimitiveBase_addObj_lpwIndices;
        ++g_DrawTriangleList_trianglesCount;
    }
}

void __cdecl dk2::MyEntryBuf_Triangle24_add(int vertIdx0, int vertIdx1, int vertIdx2, int a4) {
    unsigned int idx = g_AtlasMeshGroup_current->zeroOrM1 + a4;
    if (idx >= 0x400) idx = 1023;
    Triangle24 *pTri = &g_MyEntryBuf_Triangle24_instance.buf[g_totalTrianglesCount];
    pTri->vertIdxs[0] = g_totalVerticesCount + vertIdx0;
    pTri->vertIdxs[1] = g_totalVerticesCount + vertIdx1;
    pTri->vertIdxs[2] = g_totalVerticesCount + vertIdx2;
    pTri->renderFlags = g_AtlasMeshGroup_current->renderFlags_x2[0];
    pTri->surfhCount = g_AtlasMeshGroup_current->surfhCount;
    for (int i = 0; i < g_AtlasMeshGroup_current->surfhCount; ++i) {
        pTri->holders[i] = g_AtlasMeshGroup_current->holders[i];
    }
    pTri->prevTriangleIdx = g_sceneObj2E_f21_to_triangleIndices[idx];
    g_sceneObj2E_f21_to_triangleIndices[idx] = g_totalTrianglesCount;
    g_totalTrianglesCount++;
}
