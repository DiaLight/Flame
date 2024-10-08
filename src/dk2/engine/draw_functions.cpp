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
        if ((mydd_triangles.flags & 1) != 0) {  // 3dengine == 4
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
            DirectDraw_prepareTexture(toDraw->drawFlags_x2[texStageIdx]);
            DrawTriangleList(texStageIdx, dk2::DrawTriangleList_trianglesCount, dk2::DrawTriangleList_verticesCount);
        }
        toDraw = g_toDraw;
        ++p_fC_vertices18x2;
    }
}

void __cdecl dk2::renderer_setSurfaceHolder(SurfaceHolder *holder, uint32_t stage) {
    if(gog::SurfaceHolder_setTexture_patch::isEnabled()) {
        if(!holder) return;
    }
    if ( (mydd_scene.flags & 1) != 0 ) {  // 3dengine == 4
        mgsr_lockedBuf_dw256x256 = (uint32_t *) holder->ddsurf->v_lockBuf();
    } else {
        mydd_devTexture.d3d3_halDevice->SetTexture(stage, holder->ddsurf->devTex);
        if (holder->ddsurf->ddSurf->IsLost()) g_isCurDdSurfLost = 1;
    }
}