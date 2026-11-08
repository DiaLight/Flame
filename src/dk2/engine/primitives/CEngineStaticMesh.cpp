//
// Created by DiaLight on 6/28/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/CEngineStaticMesh.h"
#include "dk2/Obj57AD20.h"
#include "dk2/Obj57AC99.h"
#include "dk2/LightSplatBuffer.h"
#include "dk2/Obj57ACFA.h"
#include "dk2/utils/Uv2f.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/Obj58EF80.h"
#include "dk2/math/color.h"
#include "tools/visual_debug.h"
#include "dk2/engine/scene/Vertex_flags.h"
#include "patches/opengl/visual_value.h"

void dk2::CEngineStaticMesh::_addRenderObj(int a2, dk2::SceneObject2E *a3_obj2E) {
    this->pObj57AD20->_addRenderObj(
            a2,
            a3_obj2E,
            this->f8_pObj571B47,
            this->f30,
            this->f10_vertexGrids10,
            this->f14__localOffsetX,
            this->f16__localOffsetY,
            this->_diffusionAlpha);
}

void dk2::Obj57AD20::_addRenderObj(
        int a2,
        SceneObject2E *a3_obj2E,
        Obj571B47 *a4_pObj571B47,
        int a5,
        Obj58EF80 **a6_vertexGrids,
        int a7_localOffsetX,
        int a8_localOffsetY,
        float a9_diffusionAlpha) {
    if (a6_vertexGrids) {
        this->_addRenderObj_sub1(a2, a3_obj2E, a5, a4_pObj571B47, a6_vertexGrids, a7_localOffsetX, a8_localOffsetY, a9_diffusionAlpha);
    } else {
        this->_addRenderObj_sub2(a2, a3_obj2E, a5, a4_pObj571B47, a7_localOffsetX, a8_localOffsetY, a9_diffusionAlpha);
    }
}

namespace dk2 {

    Uv2f UQ15_to_Uv2f(uint32_t uv_UQ15) {  // uv UQ15 Fixed-Point Format
        // / 32768. — Normalizes the 16-bit integer to [0.0, 1.0] range. convert from UQ15 to [0.0, 1.0]
        return Uv2f {  // 32768 == 0x8000
                .u = (float) ((double) (uv_UQ15 & 0xFFFF) / 32768.),
                .v = (float) ((double) ((uv_UQ15 >> 16) & 0xFFFF) / 32768.),
        };
    }

}

void dk2::Obj57AD20::_addRenderObj_sub1(
        int a2,
        SceneObject2E *a3_obj2E,
        int a4,
        Obj571B47 *a5_pObj571B47,
        Obj58EF80 **a6_vertexGrids,
        int a7_localOffsetX,
        int a8_localOffsetY,
        float a9_diffusionAlpha) {
    static VisualBool disable("CEngine.StaticMesh/HF_sub1::disable");
    if(disable) return;

    Obj57AC99 *objPos = &this->pComplexBuf_Obj57AC99__vertice__Obj57ACFA[a2];
    int f4_MyScaledSurface_idx = objPos->MyScaledSurface_idx;
    MyScaledSurface *v11 = MyEntryBuf_MyScaledSurface_getByIdx(f4_MyScaledSurface_idx);
    __renderFun_setSceneObject2E(a3_obj2E, 1, 0, 0, a9_diffusionAlpha, a4 == 0);

    Color3f v31 = v11->color21 + this->color14 + g_color_760A98;
    if (g_value760B8C) v31 = Color3f { 255.0, 0.0, 0.0 };

    g_MyGridMeshObject_instance_781078.constructor((float) (a7_localOffsetX - 1), (float) (a8_localOffsetY - 1), a6_vertexGrids);

    f4_MyScaledSurface_idx = this->f2C;

    LightSplatBuffer v64;
    v64.count = 0;
    v64.constructor(a5_pObj571B47, f4_MyScaledSurface_idx);

    for (int i = 0; i < objPos->_trisCount; ++i) {
        Vec3ub *triPos = &objPos->pVerticeList_start[i];

        int xIdx = triPos->x;
        int yIdx = triPos->y;
        int zIdx = triPos->z;

        Obj57ACFA *xObj = &objPos->pObj28_start[xIdx];
        Obj57ACFA *yObj = &objPos->pObj28_start[yIdx];
        Obj57ACFA *zObj = &objPos->pObj28_start[zIdx];

        int xFlags = g_vertexFlags[xIdx];
        int yFlags = g_vertexFlags[yIdx];
        int zFlags = g_vertexFlags[zIdx];

        Vec3f xVec;
        Vec3f yVec;
        Vec3f zVec;

        if (!xFlags) g_MyGridMeshObject_instance_781078.sampleGridPosition(xObj->vec0.x, xObj->vec0.y, xObj->vec0.z, &xVec);
        if (!yFlags) g_MyGridMeshObject_instance_781078.sampleGridPosition(yObj->vec0.x, yObj->vec0.y, yObj->vec0.z, &yVec);
        if (!zFlags) g_MyGridMeshObject_instance_781078.sampleGridPosition(zObj->vec0.x, zObj->vec0.y, zObj->vec0.z, &zVec);

        if (!xFlags) g_RenderData_addViewProj(xIdx, &xVec);
        if (!yFlags) g_RenderData_addViewProj(yIdx, &yVec);
        if (!zFlags) g_RenderData_addViewProj(zIdx, &zVec);

        g_RenderData_apply(xIdx, yIdx, zIdx);

        if ((g_vertexFlags[xIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = xObj->color1C + v31;
            v64.accumulateDirectionalLight(&color, &xObj->vec0, &xObj->vec10);

            Uv2f uv = UQ15_to_Uv2f(zObj->uv_UQ15);

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(xIdx, cols, uvs);
        }
        if ((g_vertexFlags[yIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = yObj->color1C + v31;
            v64.accumulateDirectionalLight(&color, &yObj->vec0, &yObj->vec10);

            Uv2f uv = UQ15_to_Uv2f(zObj->uv_UQ15);

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(yIdx, cols, uvs);
        }
        if ((g_vertexFlags[zIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = zObj->color1C + v31;
            v64.accumulateDirectionalLight(&color, &zObj->vec0, &zObj->vec10);

            Uv2f uv = UQ15_to_Uv2f(zObj->uv_UQ15);

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(zIdx, cols, uvs);
        }
    }
    applyIndxs_sub_58AC20();
}

void dk2::Obj57AD20::_addRenderObj_sub2(
        int a2,
        SceneObject2E *a3,
        int a4,
        Obj571B47 *a5_pObj571B47,
        int a6_localOffsetX,
        int a7_localOffsetY,
        float a8_diffusionAlpha) {
    static VisualBool disable("CEngine.StaticMesh/HF_sub2::disable");
    if(disable) return;

    __renderFun_setSceneObject2E(a3, 1, 0, 0, a8_diffusionAlpha, a4 == 0);


    Obj57AC99 *objPos = &this->pComplexBuf_Obj57AC99__vertice__Obj57ACFA[a2];
    MyScaledSurface *scaledSurf = MyEntryBuf_MyScaledSurface_getByIdx(objPos->MyScaledSurface_idx);
    Color3f v29 = scaledSurf->color21 + this->color14 + g_color_760A98;

    LightSplatBuffer v52;
    v52.count = 0;
    v52.constructor(a5_pObj571B47, this->f2C);

    for (int i = 0; i < objPos->_trisCount; ++i) {
        Vec3ub *triPos = &objPos->pVerticeList_start[i];
        Obj57ACFA *fC_pObj28_start = objPos->pObj28_start;
        int xIdx = triPos->x;
        int yIdx = triPos->y;
        int zIdx = triPos->z;

        Obj57ACFA *xObj = &fC_pObj28_start[xIdx];
        Obj57ACFA *yObj = &fC_pObj28_start[yIdx];
        Obj57ACFA *zObj = &fC_pObj28_start[zIdx];

        if (!g_vertexFlags[xIdx]) g_RenderData_addViewProj(xIdx, &xObj->vec0);
        if (!g_vertexFlags[yIdx]) g_RenderData_addViewProj(yIdx, &yObj->vec0);
        if (!g_vertexFlags[zIdx]) g_RenderData_addViewProj(zIdx, &zObj->vec0);

        g_RenderData_apply(xIdx, yIdx, zIdx);

        if ((g_vertexFlags[xIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = xObj->color1C + v29;
            v52.accumulateDirectionalLight(&color, &xObj->vec0, &xObj->vec10);
            Uv2f uv = UQ15_to_Uv2f(xObj->uv_UQ15);

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(xIdx, cols, uvs);
        }
        if ((g_vertexFlags[yIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = yObj->color1C + v29;
            v52.accumulateDirectionalLight(&color, &yObj->vec0, &yObj->vec10);
            Uv2f uv = UQ15_to_Uv2f(yObj->uv_UQ15);

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(yIdx, cols, uvs);
        }
        if ((g_vertexFlags[zIdx] & Vertex_unvisitedColorUv) != 0) {
            Color3f color = zObj->color1C + v29;
            v52.accumulateDirectionalLight(&color, &zObj->vec0, &zObj->vec10);
            Uv2f uv = UQ15_to_Uv2f(zObj->uv_UQ15);;

            Color3f cols[2] {color, color};
            Uv2f uvs[2] {uv, uv};
            g_Vertex_setColorUv(zIdx, cols, uvs);
        }
    }
    applyIndxs_sub_58AC20();
}


/**
 * Qwen3.6 assisted decompilation
 * Trilinear Grid Interpolation - Sample vertex position from a 3D grid
 *
 * This function performs trilinear interpolation to sample a vertex position
 * at arbitrary (x, y, z) coordinates from a structured 3D grid of vertices.
 *
 * Algorithm:
 * 1. Convert input coordinates to grid indices (grid_x, grid_y, grid_z)
 *    using a bit-manipulation trick that maps float values to grid cell indices
 * 2. Perform boundary check - if outside grid bounds, return input coordinates as-is
 * 3. Look up the 8 corner vertices of the grid cell containing the point
 * 4. Compute normalized coordinates within the cell (coord_x/y/z in [0, 1))
 * 5. Perform trilinear interpolation using the 8 corner vertices
 *
 * The grid index extraction uses a clever bit-casting technique:
 *   - Adds offset to normalize float to [1, 2) range (biased exponent = 0x3F000000)
 *   - Extracts mantissa bits (mask 0x7FFFFF) to get fractional grid position
 *   - Subtracts bias (0x400001) to get the actual grid cell index
 *
 * This is essentially a bilinear interpolation extended to 3D (trilinear),
 * commonly used in 3D mesh rendering for sampling positions from organized
 * vertex grids (similar to texture sampling but for geometry).
 *
 * @param x    World X coordinate to sample
 * @param y    World Y coordinate to sample
 * @param z    World Z coordinate to sample
 * @param output   Output Vec3f pointer to store interpolated result
 * @return     The input pointer a5 (for method chaining)
 */
dk2::Vec3f *dk2::MyGridMeshObject::sampleGridPosition(float x, float y, float z, Vec3f *output) {
    // Compute relative coordinates
    double rel_x = x - this->localOffsetX;
    double rel_y = y - this->localOffsetY;
    double rel_z = z - -2.5;

    // Bit-cast float to uint32_t for grid index extraction
    // Pattern: normalize to [1, 2) range, extract mantissa bits, adjust
    float temp_x = 12582912.0 - (0.49998999 - (rel_x + rel_x + 1.0));
    unsigned int grid_x = ((*(uint32_t*)(&temp_x)) & 0x7FFFFF) - 0x400001;

    float temp_y = 12582912.0 - (0.49998999 - (rel_y + rel_y + 1.0));
    unsigned int grid_y = ((*(uint32_t*)(&temp_y)) & 0x7FFFFF) - 0x400001;

    float temp_z = 12582912.0 - (0.49998999 - (rel_z + rel_z + 1.0));
    unsigned int grid_z = ((*(uint32_t*)(&temp_z)) & 0x7FFFFF) - 0x400001;

    // Boundary check - exit early if coordinates are out of grid bounds
    if (grid_x > 4 || grid_y > 4 || grid_z > 3) {
        output->x = x;
        output->y = y;
        output->z = z;
        return output;
    }

    // Look up grid coordinates from global table
    uint8_t *grid_lookup = &g_unk780E78[8 * (grid_y + 8 * grid_x)];

    Vec3f *const corner0 = &this->vertexGrids[grid_lookup[0]]->arr[0][0][0];
    Vec3f *const corner1 = &this->vertexGrids[grid_lookup[1]]->arr[0][0][0];
    Vec3f *const corner2 = &this->vertexGrids[grid_lookup[2]]->arr[0][0][0];
    Vec3f *const corner3 = &this->vertexGrids[grid_lookup[3]]->arr[0][0][0];

    // Compute indices for the Z-axis interpolation
    // Each grid row has 2 vertices along Z (offset by grid_z and lookup offset)
    const int base_idx = static_cast<int>(grid_z);

    // Near-Z vertices (first row along Z for each corner)
    Vec3f *v_near_0 = &corner0[(base_idx + grid_lookup[4])];
    Vec3f *v_near_1 = &corner1[(base_idx + grid_lookup[5])];
    Vec3f *v_near_2 = &corner2[(base_idx + grid_lookup[6])];
    Vec3f *v_near_3 = &corner3[(base_idx + grid_lookup[7])];

    // Far-Z vertices (second row along Z for each corner)
    Vec3f *v_far_0 = &corner0[base_idx + grid_lookup[4] + 1];
    Vec3f *v_far_1 = &corner1[base_idx + grid_lookup[5] + 1];
    Vec3f *v_far_2 = &corner2[base_idx + grid_lookup[6] + 1];
    Vec3f *v_far_3 = &corner3[base_idx + grid_lookup[7] + 1];

    // Compute normalized coordinates within the grid cell
    float abs_x = static_cast<float>(rel_x);
    float coord_x = abs_x + abs_x - (double) (int) grid_x;

    float abs_y = static_cast<float>(rel_y);
    double coord_y = abs_y + abs_y - (double) (grid_y);

    float abs_z = static_cast<float>(rel_z);
    double coord_z = abs_z + abs_z - (double) (int) grid_z;

    // Compute interpolation weights
    // coord_x, coord_y, coord_z are the normalized positions [0, 1) within the grid cell
    // inv_* are the complementary weights (1 - coord)
    float inv_x = 1.0 - coord_x;
    float inv_y = 1.0 - coord_y;
    float inv_z_val = 1.0 - coord_z;

    // XY plane weights (before Z interpolation)
    // w[near/far]_x[y/z] pattern matches original:
    double w_corner0_near = inv_y * inv_x * inv_z_val;
    double w_corner1_near = inv_y * coord_x * inv_z_val;
    double w_corner2_near = coord_y * inv_x * inv_z_val;
    double w_corner3_near = coord_y * coord_x * inv_z_val;

    double w_corner0_far = (float) (inv_y * inv_x) * (float) coord_z;
    double w_corner1_far = (float) (inv_y * coord_x) * (float) coord_z;
    double w_corner2_far = (float) (coord_y * inv_x) * (float) coord_z;
    double w_corner3_far = (float) (coord_y * coord_x) * (float) coord_z;

    // Trilinear interpolation: X component
    float x_result = static_cast<float>(
            v_near_0->x * w_corner0_near +
            v_near_1->x * w_corner1_near +
            v_near_2->x * w_corner2_near +
            v_near_3->x * w_corner3_near +
            v_far_0->x * w_corner0_far +
            v_far_1->x * w_corner1_far +
            v_far_2->x * w_corner2_far +
            v_far_3->x * w_corner3_far
    );

    // Trilinear interpolation: Y component
    float y_result = static_cast<float>(
            v_near_0->y * w_corner0_near +
            v_near_1->y * w_corner1_near +
            v_near_2->y * w_corner2_near +
            v_near_3->y * w_corner3_near +
            v_far_0->y * w_corner0_far +
            v_far_1->y * w_corner1_far +
            v_far_2->y * w_corner2_far +
            v_far_3->y * w_corner3_far
    );

    // Trilinear interpolation: Z component
    float z_result = static_cast<float>(
            v_near_0->z * w_corner0_near +
            v_near_1->z * w_corner1_near +
            v_near_2->z * w_corner2_near +
            v_near_3->z * w_corner3_near +
            v_far_0->z * w_corner0_far +
            v_far_1->z * w_corner1_far +
            v_far_2->z * w_corner2_far +
            v_far_3->z * w_corner3_far
    );

    output->x = x_result;
    output->y = y_result;
    output->z = z_result;
    return output;
}
