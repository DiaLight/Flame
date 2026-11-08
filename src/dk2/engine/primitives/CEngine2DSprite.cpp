//
// Created by DiaLight on 1/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/engine/primitive/2d/CEngine2DSprite.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "dk2/utils/TexCoord.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyD3D3Vertex.h"
#include "dk2/Triangle34.h"
#include "dk2/utils/Idx3us.h"
#include "dk2/math/vec.h"
#include "tools/visual_debug.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "patches/opengl/visual_value.h"
#include <cmath>
#include <algorithm>


void __cdecl dk2::CEngine2DSprite_create(
        int a1_posX,
        int a2_posY,
        int a3_texW,
        int a4_texH,
        float a5_z,
        int idx,
        Vec3f v54_vec,
        float a10_a,
        float a11,
        uint32_t a12_createFlags) {
    if (a3_texW <= 0) return;
    while (true) {
        CEnginePrimitiveBase *obj = NULL;
        if (a4_texH <= 0) break;
        CEngine2DSprite *newObj = (CEngine2DSprite *) MyHeap_alloc(sizeof(CEngine2DSprite));
        int try_level = 0;
        if (newObj) {
            obj = ((CEngine2DSprite *) newObj)->constructor(
                    a1_posX, a2_posY,
                    a3_texW, a4_texH,
                    a5_z,
                    v54_vec.x, v54_vec.y, v54_vec.z,
                    a10_a,
                    a12_createFlags,
                    g_viewPos_765218.x, g_viewEnd_765228.x, g_viewPos_765218.y, g_viewEnd_765228.y);
        }
        try_level = -1;
        obj->f0_byConstructor_prev = g_Meshes2D_byConstructor_last;
        g_Meshes2D_byConstructor_last = obj;
        BOOL needUpscale = 1;
        if( a1_posX < g_viewPos_765218.x) needUpscale = 0;
        if (a3_texW + a1_posX > g_viewEnd_765228.x) needUpscale = 0;
        if (a2_posY < g_viewPos_765218.y) needUpscale = 0;
        if (a4_texH + a2_posY > g_viewEnd_765228.y) needUpscale = 0;
        MyScaledSurface *Prescaled;
        if (needUpscale)
            Prescaled = MyDblNamedSurface_createPrescaled(idx, a3_texW, a4_texH);
        else
            Prescaled = MyEntryBuf_MyScaledSurface_getByIdx(idx);
        int scaleIdx;
        {
//            int f15_prob_height = Prescaled->prob_height;
//            float a12a = (double) f15_prob_height * a11 - -0.0009765625 - 0.49998999 - -12582912.0;
//            scaleIdx = (((DWORD) a12a) & 0x7FFFFF) - 0x400000;
//            if (scaleIdx < 0) scaleIdx = 0;
//            if (scaleIdx >= f15_prob_height) scaleIdx = f15_prob_height - 1;
            // above is optimized version of
            scaleIdx = std::clamp<int>(
                    std::round((double) Prescaled->prob_height * a11),
                    0, Prescaled->prob_height - 1
            );
        }
        MyCESurfHandle *surfh = Prescaled->scaledSurfArr[scaleIdx].surfScaledArr[0];
        uint32_t _renderFlags = Prescaled->renderFlags;
        uint32_t _mask;
        uint32_t _flags;
        transformFlags(a12_createFlags, &_mask, &_flags);
        unsigned int renderFlags = _flags | _renderFlags & _mask;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0)
            renderFlags = renderFlags & ~RenderState_zEnable | RenderState_use3DPipeline;
        MyCESurfHandle_static_addToHashList_flagsOr400(surfh, renderFlags);
        int objIdx = SceneObject2E_count;
        if (SceneObject2E_count >= SceneObject2EList_instance.maxCount) {
            SceneObject2EList_instance.enlarge(SceneObject2E_count);
            objIdx = SceneObject2E_count;
        }
        SceneObject2E &sobj = SceneObject2EList_instance.arr[objIdx];
        sobj.mesh = obj;
        sobj.f2C_ = 0;
        sobj.lod__triangleCount = 2;
        sobj.numVertsEx = 4;
        sobj.renderFlags_x2[0] = renderFlags;
        sobj.currentDepthMode = g_depthMode_7820A0;
        sobj.surfhCount = 1;
        sobj.texStagesCount = 1;
        sobj.numTextureSamplers_x2[0] = 1;
        sobj.surfh_x4[0] = surfh;
        sobj.zeroOrM1 = 0;
        SceneObject2E_count++;
        if ((a12_createFlags & 0x40) == 0) break;
        a12_createFlags = a12_createFlags & ~0x42u | 2;
        a5_z = a5_z - static_765214;
    }
}

void dk2::CEngine2DSprite::_addRenderObj(int a2, SceneObject2E *a3_obj) {
    static VisualBool noViewFilter("CEngine.2DSprite::noViewFilter");
    if(!noViewFilter) {
        if ((f4_posX + this->f8_texW) <= this->f24_viewLeft24) return;
        if ((f6_posY + this->fA_texH) <= this->f28_viewTop28) return;
        if (f4_posX >= this->f26_viewRight26) return;
        if (f6_posY >= this->f2A_viewBottom2A) return;
    }
    static VisualBool disable("CEngine.2DSprite::disable");
    if(disable) return;
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        if ((a3_obj->renderFlags_x2[0] & RenderState_fl2000) != 0) {
            this->createTriangle34(0, a3_obj);
        } else {
            this->addVert18Triangle(0, a3_obj);
        }
    } else {
        this->addMyD3D3VertexTriangle(0, a3_obj);
    }
}

dk2::Triangle34 *dk2::CEngine2DSprite::createTriangle34(int a2, SceneObject2E *a3) {
    int v17 = 0;
    int texH = this->fA_texH;
    __int16 posX = this->f4_posX;
    int posY = this->f6_posY;
    int texW = this->f8_texW;

    __int16 viewLeft24 = this->f24_viewLeft24;
    if (posX < viewLeft24) {
        this->f4_posX = viewLeft24;
        v17 = ((viewLeft24 - posX) << 8) / texW;
    }
    __int16 viewTop28 = this->f28_viewTop28;
    int v10;
    if (this->f6_posY >= viewTop28) {
        v10 = 0;
    } else {
        this->f6_posY = viewTop28;
        v10 = ((viewTop28 - posY) << 8) / texH;
    }

    int viewRight26 = posX + texW;
    if (viewRight26 > this->f26_viewRight26)
        viewRight26 = this->f26_viewRight26;

    int viewBottom2A = texH + posY;
    if (viewBottom2A > this->f2A_viewBottom2A)
        viewBottom2A = this->f2A_viewBottom2A;
    MyCESurfHandle *f1C_curReduction = a3->surfh_x4[0]->curReduction;

    float v20 = 12582912.0 - (0.49998999 - f1C_curReduction->texUAdd * 256.0);
    float v19 = 12582912.0 - (0.49998999 - f1C_curReduction->texVAdd * 256.0);
    float v24 = 12582912.0 - (0.49998999 - this->fC_posZ * 0.1 * 1024.0);
    float v25 = this->f10_r * 255.0 - 0.49998999 - -12582912.0;
    float v22 = this->f14_g * 255.0 - 0.49998999 - -12582912.0;
    float v23 = this->f18_b * 255.0 - 0.49998999 - -12582912.0;
    float v21 = this->f1C_a * 255.0 - 0.49998999 - -12582912.0;
    Triangle34 *result = Triangle34_add(((*(uint32_t *) &v24) & 0x7FFFFF) - 0x400000);
    result->renderFlags = a3->renderFlags_x2[0];
    result->holders[0] = a3->surfh_x4[0]->curReduction->holder_parent;
    result->srcX = this->f4_posX;
    result->srcY = this->f6_posY;
    result->dstX = ((*(uint32_t *) &v20) & 0x7FFFFF) + v17 - 0x400000;
    result->dstY = ((*(uint32_t *) &v19) & 0x7FFFFF) + v10 - 0x400000;
    result->width = viewRight26 - this->f4_posX;
    result->height = viewBottom2A - this->f6_posY;

    result->unk = ((*(uint32_t *) &v23) & 0x7FFFFF) + ((
            ((*(uint32_t *) &v22) & 0x7FFFFF) + ((
                    ((*(uint32_t *) &v25) & 0x7FFFFF) + ((
                            (*(uint32_t *) &v21) & 0x7FFFFF
                    ) << 8) + 0xBFC0
            ) << 8)
    ) << 8);
    return result;
}

dk2::Triangle34 *__cdecl dk2::Triangle34_add(unsigned int idx) {
    if (idx >= 1024) idx = 1023;
    if ((unsigned int) (g_Triangle34_count + 1) >= g_MyEntryBuf_Triangle34_instance.maxCount) {
        unsigned int f4_maxCount = g_MyEntryBuf_Triangle34_instance.maxCount;
        do
            f4_maxCount += g_MyEntryBuf_Triangle34_instance.expandCount;
        while (f4_maxCount <= g_Triangle34_count + 1);
        Triangle34 *newBuf = (Triangle34 *) MyHeap_alloc(sizeof(Triangle34) * f4_maxCount);
        // copy old
        for (int i = 0; i < g_MyEntryBuf_Triangle34_instance.maxCount; ++i) {
            newBuf[i] = g_MyEntryBuf_Triangle34_instance.buf[i];
        }
        MyHeap_free(g_MyEntryBuf_Triangle34_instance.buf);
        g_MyEntryBuf_Triangle34_instance.buf = newBuf;
        g_MyEntryBuf_Triangle34_instance.maxCount = f4_maxCount;
    }
    Triangle34 *result = &g_MyEntryBuf_Triangle34_instance.buf[g_Triangle34_count];
    result->prevTriangleIdx = g_sceneObj2E_f21_to_triangleIndices[idx];
    g_sceneObj2E_f21_to_triangleIndices[idx] = g_Triangle34_count | 0x40000000;
    result->surfhCount = 1;
    ++g_Triangle34_count;
    return result;
}

void dk2::CEngine2DSprite::addMyD3D3VertexTriangle(int a2, SceneObject2E *a3) {
    double leftNorm;
    int left;
    int x = this->f4_posX;
    if (x < this->f24_viewLeft24) {
        left = this->f24_viewLeft24;
        leftNorm = (double) (this->f24_viewLeft24 - x) / (double) this->f8_texW;
    } else {
        left = this->f4_posX;
        leftNorm = 0.0;
    }
    this->f4_posX = left;

    float topNorm;
    int top;
    int y = this->f6_posY;
    if (y < this->f28_viewTop28) {
        top = this->f28_viewTop28;
        topNorm = (double) (this->f28_viewTop28 - y) / (double) this->fA_texH;
    } else {
        top = this->f6_posY;
        topNorm = 0.0;
    }
    this->f6_posY = top;

    float rightNorm;
    int right;
    int w = this->f4_posX + this->f8_texW;
    if (w > this->f26_viewRight26) {
        right = this->f26_viewRight26;
        rightNorm = (double) (this->f26_viewRight26 - w) / (double) this->f8_texW + 1.0;
    } else {
        right = w;
        rightNorm = 1.0;
    }

    float bottomNorm;
    int bottom;
    int h = this->f6_posY + this->fA_texH;
    if (h > this->f2A_viewBottom2A) {
        bottom = this->f2A_viewBottom2A;
        bottomNorm = (double) (this->f2A_viewBottom2A - h) / (double) this->fA_texH + 1.0;
    } else {
        bottom = h;
        bottomNorm = 1.0;
    }

    DWORD leftTopIdx = g_DrawTriangleList_verticesCount;
    DWORD rightTopIdx = g_DrawTriangleList_verticesCount + 1;
    DWORD rightBottomIdx = g_DrawTriangleList_verticesCount + 2;
    DWORD leftBottomIdx = g_DrawTriangleList_verticesCount + 3;
    g_DrawTriangleList_verticesCount += 4;

    MyD3D3Vertex *pLeftTop = (MyD3D3Vertex *) ((char *) g_vertices[0].MyD3D3Vertex_pos + leftTopIdx * g_MyD3D3Vertex_size);
    MyD3D3Vertex *pRightTop = (MyD3D3Vertex *) ((char *) g_vertices[0].MyD3D3Vertex_pos + rightTopIdx * g_MyD3D3Vertex_size);
    MyD3D3Vertex *pRightBottom = (MyD3D3Vertex *) ((char *) g_vertices[0].MyD3D3Vertex_pos + rightBottomIdx * g_MyD3D3Vertex_size);
    MyD3D3Vertex *pLeftBottom = (MyD3D3Vertex *) ((char *) g_vertices[0].MyD3D3Vertex_pos + leftBottomIdx * g_MyD3D3Vertex_size);

    float v37_R = 12582912.0 - (0.49998999 - this->f10_r * 255.0);
    uint32_t r_ = (*(uint32_t *) &v37_R) & 0x7FFFFF;
    float v33_G = 12582912.0 - (0.49998999 - this->f14_g * 255.0);
    uint32_t g_ = (*(uint32_t *) &v33_G) & 0x7FFFFF;
    float v27_B = 12582912.0 - (0.49998999 - this->f18_b * 255.0);
    uint32_t b_ = (*(uint32_t *) &v27_B) & 0x7FFFFF;
    float v35_A = 12582912.0 - (0.49998999 - this->f1C_a * 255.0);
    uint32_t a_ = (*(uint32_t *) &v35_A) & 0x7FFFFF;
    int v18_diffuse = b_ + ((
            g_ + ((
                    r_ + (
                            a_ << 8
                    ) + 0xBFC0
            ) << 8)
    ) << 8);

    MyCESurfHandle *f1C_curReduction = a3->surfh_x4[0]->curReduction;

    float uRight = f1C_curReduction->texUMul * rightNorm + f1C_curReduction->texUAdd;
    float uLeft = f1C_curReduction->texUMul * leftNorm + f1C_curReduction->texUAdd;
    float vBottom = f1C_curReduction->texVMul * bottomNorm + f1C_curReduction->texVAdd;
    float vTop = f1C_curReduction->texVMul * topNorm + f1C_curReduction->texVAdd;

    float posZ_div10 = this->fC_posZ * 0.1;
    pLeftTop->vec = Vec3f {(float) left, (float) top, posZ_div10 };
    pLeftTop->oneDivZ = 1.0;
    pLeftTop->diffuse = v18_diffuse;
    pLeftTop->tex[0] = TexCoord {uLeft, vTop };

    pRightTop->vec = Vec3f {(float) right, (float) top, posZ_div10 };
    pRightTop->oneDivZ = 1.0;
    pRightTop->diffuse = v18_diffuse;
    pRightTop->tex[0] = TexCoord {uRight, vTop };

    pRightBottom->vec = Vec3f {(float) right, (float) bottom, posZ_div10 };
    pRightBottom->oneDivZ = 1.0;
    pRightBottom->diffuse = v18_diffuse;
    pRightBottom->tex[0] = TexCoord {uRight, vBottom };

    pLeftBottom->vec = Vec3f {(float) left, (float) bottom, posZ_div10 };
    pLeftBottom->oneDivZ = 1.0;
    pLeftBottom->diffuse = v18_diffuse;
    pLeftBottom->tex[0] = TexCoord {uLeft, vBottom };

    if ((a3->renderFlags_x2[0] & RenderState_use3DPipeline) != 0) {
        int value = strangeOptimizedMultiplyAddCast(posZ_div10, 1024.0, 0);
        MyEntryBuf_Triangle24_add(leftTopIdx, rightTopIdx, rightBottomIdx, value);
        MyEntryBuf_Triangle24_add(leftTopIdx, rightBottomIdx, leftBottomIdx, value);
    } else {
        *g_CEnginePrimitiveBase_addObj_lpwIndices = Idx3us { .i=(uint16_t) leftTopIdx, .j=(uint16_t) rightTopIdx, .k=(uint16_t) rightBottomIdx };
        ++g_CEnginePrimitiveBase_addObj_lpwIndices;
        ++g_DrawTriangleList_trianglesCount;

        *g_CEnginePrimitiveBase_addObj_lpwIndices = Idx3us { .i=(uint16_t) leftTopIdx, .j=(uint16_t) rightBottomIdx, .k=(uint16_t) leftBottomIdx };
        ++g_CEnginePrimitiveBase_addObj_lpwIndices;
        ++g_DrawTriangleList_trianglesCount;
    }
}


