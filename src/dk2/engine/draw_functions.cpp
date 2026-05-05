//
// Created by DiaLight on 10.09.2024.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/Vertex18.h"
#include "dk2/ToDraw.h"
#include "dk2/SurfaceHolder.h"
#include "dk2/CEngineDDSurface.h"
#include "gog_patch.h"
#include "dk2/Vertex18.h"
#include "dk2/Triangle24.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/engine/primitive/CEnginePrimitiveBase.h"


void __cdecl dk2::addObjectToDraw(ToDraw *obj30) {
    g_toDraw = obj30;
    DrawTriangleList_verticesCount = 0;
    DrawTriangleList_trianglesCount = 0;
    unsigned int totalTrianglesCount = g_totalTrianglesCount + 4 * obj30->totalTriangles;
    unsigned int totalVerticesCount = g_totalVerticesCount + 4 * obj30->totalVertices;
    int v3_flags = obj30->drawFlags_x2[0];
    if ((MyDirectDraw_instance_triangles.flags & 1) != 0) {
        if ((v3_flags & 0x200) != 0) {
            if (totalVerticesCount >= MyEntryBuf_Vertex18_instance.maxCount)
                MyEntryBuf_Vertex18_instance.resize(totalVerticesCount);
            g_vertices[0].vertices18hx2_pos = &MyEntryBuf_Vertex18_instance.buf[g_totalVerticesCount];
            if (totalTrianglesCount >= MyEntryBuf_Triangle24_instance.maxCount)
                MyEntryBuf_Triangle24_instance.resize(totalTrianglesCount);
        } else {
            for (int i = 0; i < 2; ++i) {
                g_vertices[i].vertices18hx2_pos = g_vertices[i].vertices18x2;
            }
            g_lpwTrianglesIndices = (Idx3s *) DrawTriangleList_lpwIndices;
        }
    } else if ((v3_flags & 0x200) != 0) {
        if ((int) totalVerticesCount > g_flexibleVertices_maxCount) {
            void *v5 = MyHeap_alloc(g_flexibleVertex_size * (g_flexibleVertices_maxCount + 512));
            memcpy(v5, g_flexibleVertices, g_flexibleVertices_maxCount * g_flexibleVertex_size);
            MyHeap_free(g_flexibleVertices);
            g_flexibleVertices = v5;
            g_flexibleVertices_maxCount += 512;
        }
        unsigned int f4_maxCount = MyEntryBuf_uint16_indices_instance.maxCount;
        if (totalVerticesCount >= MyEntryBuf_uint16_indices_instance.maxCount) {
            do
                f4_maxCount += MyEntryBuf_uint16_indices_instance.expandCount;
            while (f4_maxCount <= totalVerticesCount);
            WORD *v7_indices = (WORD *) MyHeap_alloc(sizeof(WORD) * f4_maxCount);
            unsigned int v8_maxCount = MyEntryBuf_uint16_indices_instance.maxCount;
            WORD *v9 = v7_indices;
            if (MyEntryBuf_uint16_indices_instance.maxCount) {
                memcpy(v7_indices, MyEntryBuf_uint16_indices_instance.buf, 2 * MyEntryBuf_uint16_indices_instance.maxCount);
                v8_maxCount = MyEntryBuf_uint16_indices_instance.maxCount;
            }
            if (v8_maxCount < f4_maxCount) {
                WORD *v10 = &v7_indices[v8_maxCount];
                unsigned int v11 = f4_maxCount - v8_maxCount;
                do {
                    if (v10)
                        *v10 = -1;
                    ++v10;
                    --v11;
                } while (v11);
            }
            MyHeap_free(MyEntryBuf_uint16_indices_instance.buf);
            MyEntryBuf_uint16_indices_instance.buf = v9;
            MyEntryBuf_uint16_indices_instance.maxCount = f4_maxCount;
        }
        unsigned int v12_maxCount = MyEntryBuf_Triangle24_instance.maxCount;
        g_vertices[0].verticies1C_pos = (Vertex1C *) ((char *) g_flexibleVertices +
                                                      g_totalVerticesCount * g_flexibleVertex_size);
        if (totalTrianglesCount >= MyEntryBuf_Triangle24_instance.maxCount) {
            do
                v12_maxCount += MyEntryBuf_Triangle24_instance.expandCount;
            while (v12_maxCount <= totalTrianglesCount);
            Triangle24 *v13_triangles = (Triangle24 *) MyHeap_alloc(sizeof(Triangle24) * v12_maxCount);
            if (MyEntryBuf_Triangle24_instance.maxCount)
                memcpy(
                        v13_triangles,
                        MyEntryBuf_Triangle24_instance.buf,
                        sizeof(Triangle24) * MyEntryBuf_Triangle24_instance.maxCount
                );
            MyHeap_free(MyEntryBuf_Triangle24_instance.buf);
            MyEntryBuf_Triangle24_instance.buf = v13_triangles;
            MyEntryBuf_Triangle24_instance.maxCount = v12_maxCount;
        }
    } else {
        for (int i = 0; i < 2; ++i) {
            g_vertices[i].verticies1C_pos = g_vertices[i].verticies1C;
        }
        g_lpwTrianglesIndices = (Idx3s *) DrawTriangleList_lpwIndices;
    }
}

void dk2::drawTexToSurfTriangles() {
    ToDraw *toDraw = g_toDraw;
    if ((g_toDraw->drawFlags_x2[0] & 0x200) != 0) {
        g_totalVerticesCount += dk2::DrawTriangleList_verticesCount;
        g_totalTrianglesCount += dk2::DrawTriangleList_trianglesCount;
        return;
    }
    if (!dk2::DrawTriangleList_verticesCount) return;
    int holderIdx = 0;
    if (!g_toDraw->propsCount) return;
    VerticesData *p_fC_vertices18x2 = dk2::g_vertices;
    for(signed int texStageIdx = 0; texStageIdx < g_toDraw->propsCount; ++texStageIdx) {
        for(signed int stage = 0; stage < g_toDraw->numTextureSamplers_x2[texStageIdx]; ++stage) {
            SurfaceHolder *holder = toDraw->holders[holderIdx];
            renderer_setSurfaceHolder(holder, stage);
            toDraw = g_toDraw;
            ++holderIdx;
        }
        if ((MyDirectDraw_instance_triangles.flags & 1) != 0) {  // 3dengine == 4
            mgsr_setDrawFun(toDraw->drawFlags_x2[texStageIdx]);
            if (dk2::DrawTriangleList_trianglesCount) {
                Vec3s *vertIndexPos = dk2::DrawTriangleList_lpwIndices;
                int trianglesLeft = dk2::DrawTriangleList_trianglesCount;
                do {
                    mgsr_drawTriangle24_impl5(
                            (__m64 *) &p_fC_vertices18x2->vertices18x2[vertIndexPos->x],
                            (__m64 *) &p_fC_vertices18x2->vertices18x2[vertIndexPos->y],
                            (__m64 *) &p_fC_vertices18x2->vertices18x2[vertIndexPos->z]
                    );
                    ++vertIndexPos;
                    --trianglesLeft;
                } while (trianglesLeft);
            }
            _m_empty();
        } else {
            MyDirectDraw_prepareTexture(toDraw->drawFlags_x2[texStageIdx]);
            MyDirectDraw_DrawTriangleList(texStageIdx, dk2::DrawTriangleList_trianglesCount, dk2::DrawTriangleList_verticesCount);
        }
        toDraw = g_toDraw;
        ++p_fC_vertices18x2;
    }
}


namespace dk2 {

    void sub1(ToDraw *obj30, SceneObject2E *cur,
              SurfaceHolder **parents) {
        for (int i = 0; i < cur->surfhCount; ++i) {
            obj30->holders[i] = parents[i];
        }
        for (int i = 0; i < cur->propsCount; ++i) {
            obj30->drawFlags_x2[i] = cur->drawFlags_x2[i];
            obj30->numTextureSamplers_x2[i] = cur->numTextureSamplers_x2[i];
        }
        obj30->surfhCount = cur->surfhCount;
        obj30->zeroOrM1 = cur->zeroOrM1;
        obj30->propsCount = cur->propsCount;
        obj30->totalTriangles = 0;
        obj30->totalVertices = 0;
        obj30->pObj2E = NULL;
    }
    bool sub2_sameFlags(SceneObject2E *cur, ToDraw *obj30) {
        for (int j = 0; j < cur->propsCount; ++j) {
            if (obj30->drawFlags_x2[j] != cur->drawFlags_x2[j]) return false;
        }
        return true;
    }
    bool sub3_sameHolders(SceneObject2E *cur, SurfaceHolder **holders, ToDraw *obj30) {
        if (obj30->surfhCount != cur->surfhCount) return false;
        for (int j = 1; j < cur->surfhCount; ++j) {
            if (obj30->holders[j] != holders[j]) return false;
        }
        return true;
    }

}

void dk2::draw3dScene() {
    __probablySortSurfListX3_593F20();
    int objectsToDraw_count_ = SceneObject2E_count;
    ToDraw *last_ = NULL;
    if (SceneObject2E_count >= ToDrawList_instance.maxCount) {
        ToDrawList_instance.enlarge(SceneObject2E_count);
        objectsToDraw_count_ = SceneObject2E_count;
    }
    int o30idx = 0;
    SurfaceHolder *parents[4];
    for (int objIdx = 0; objIdx < objectsToDraw_count_; ++objIdx) {
        SceneObject2E *cur = &SceneObject2EList_instance.arr[objIdx];
        for (int i = 0; i < cur->surfhCount; ++i) {
            parents[i] = cur->surfh_x4[i]->curReduction->holder_parent;
        }
        ToDraw *obj30 = parents[0]->ToDraw;
        for (; obj30; obj30 = obj30->next) {
            if (obj30->propsCount != cur->propsCount) continue;
            if (obj30->zeroOrM1 != cur->zeroOrM1) continue;
            if(!sub2_sameFlags(cur, obj30)) continue;
            if(!sub3_sameHolders(cur, parents, obj30)) continue;
            break;
        }
        if (obj30) {
            if (cur->lod__triangleCount + obj30->totalTriangles > 256)
                obj30 = NULL;
        }
        if (!obj30) {
            obj30 = &ToDrawList_instance.toDrawArr[o30idx];
            sub1(obj30, cur, parents);
            {
                SurfaceHolder *par = parents[0];
                obj30->next = par->ToDraw;
                par->ToDraw = obj30;
            }
            {
                obj30->prev_eos = last_;
                last_ = obj30;
            }
            ++o30idx;
        }
        cur->next = obj30->pObj2E;
        obj30->pObj2E = cur;
        obj30->totalTriangles += cur->lod__triangleCount;
        obj30->totalVertices += cur->numVertsEx;
    }
    for (ToDraw *cur = last_; cur; cur = cur->prev_eos) {
        addObjectToDraw(cur);
        for (SceneObject2E *i = cur->pObj2E; i; i = i->next)
            i->mesh->v___addRenderObj((unsigned __int16) i->f2C_, i);
        drawTexToSurfTriangles();
        cur->holders[0]->ToDraw = NULL;
    }
    SceneObject2E_count = 0;
}


void __cdecl dk2::renderer_setSurfaceHolder(SurfaceHolder *holder, uint32_t stage) {
    if(gog::SurfaceHolder_setTexture_patch::isEnabled()) {
        if(!holder) return;
    }
    if ( (MyDirectDraw_instance.flags & 1) != 0 ) {  // 3dengine == 4
        mgsr_lockedBuf_dw256x256 = (uint32_t *) holder->surf->v_lockBuf();
    } else {
        CEngineDDSurface *ddsurf = (CEngineDDSurface *) holder->surf;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetTexture(stage, ddsurf->devTex);
        if (ddsurf->ddSurf->IsLost()) g_sc_isCurDdSurfLost = 1;
    }
}