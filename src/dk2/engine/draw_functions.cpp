//
// Created by DiaLight on 10.09.2024.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/Vertex18.h"
#include "dk2/AtlasMeshGroup.h"
#include "dk2/RenderStageTex.h"
#include "dk2/CEngineDDSurface.h"
#include "dk2/SurfHashList2.h"
#include "dk2/SurfHashList.h"
#include "gog_patch.h"
#include "dk2/Triangle24.h"
#include "dk2/SceneObject2E.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyD3D3Vertex.h"
#include "dk2/engine/scene/MyDirectDraw_flags.h"
#include "patches/logging.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicHeightField.h"
#include "dk2/engine/primitive/CEngineStaticMesh.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "dk2/engine/primitives/CEnginePrimitiveBase_dump.h"
#include "dk2/AppendObject2EArgs.h"
#include "dk2/NewObj571B3B.h"
#include "dk2/engine/primitive/2d/CEngineSprite.h"
#include "dk2/engine/primitive/2d/world/CEngineDynamicMesh.h"
#include "patches/opengl/visual_value.h"

#include <sstream>


void dk2::appendAllToSceneObject2EList() {
    for (NewObj571B3B *i = g_pNewObj571B3B_root; i; i = i->np) {
        static VisualBool showLightSources("showLightSources");
        if (g_showLightSources || showLightSources) NewObj571B3B_addLightSourceObjects(i, 1, 0);

        AppendObject2EArgs args;
        args.f0 = i->a2_x;
        args.f4 = i->a3_y;
        args.pObj571B47 = &i->pObj571B47;
        args.f10 = i->_end;

        if ((i->flags & 0x80) != 0) {
            args.pVertexGrids = i->vertexGrids44;
            g_MyGridMeshObject_instance_781078.constructor((float) (i->a2_x - 1), (float) (i->a3_y - 1), i->vertexGrids44);
        } else {
            args.pVertexGrids = NULL;
        }

        g_MyGridMeshObject_instance_781088.constructor((float) (i->a2_x - 1), (float) (i->a3_y - 1), i->vertexGrids84);

        for (CEngineSprite *j = (CEngineSprite *) i->Meshes3dStatic_byConstructor_last;
             j; j = (CEngineSprite *) j->f0_byConstructor_prev) {
            j->v_CEngineSprite_appendToSceneObject2EList(&args);
        }
        for (CEngineDynamicMesh *k = (CEngineDynamicMesh *) i->Meshes3dDynamic_byConstructor_last;
             k; k = (CEngineDynamicMesh *) k->f0_byConstructor_prev) {
            k->v_f8_appendToSceneObject2EList(&args);
        }
        i->flags &= ~8u;
    }
}


void dk2::transformFlags(int16_t createFlags, uint32_t *out_mask, uint32_t *out_flags) {
    *out_mask = 0xFFFFFFFF;
    *out_flags = 0;
    if ((createFlags & 0x2001) != 0) {
        *out_mask &= ~(RenderState_zWriteEnable | RenderState_alphaBlendOne);
        *out_flags |= RenderState_use3DPipeline | RenderState_alphaBlendSrc;
    }
    if ((createFlags & 0x2000) != 0 && (MyDirectDraw_instance.flags & MyDirectDraw_unc40) != 0) {
        *out_flags |= RenderState_diffuseAlpha;
    }
    if ((createFlags & 2) != 0) {
        *out_mask &= ~(RenderState_zWriteEnable | RenderState_useLightSplat | RenderState_alphaBlendSrc);
        *out_flags |= RenderState_use3DPipeline | RenderState_alphaBlendOne;
    }
    if ((createFlags & 0x20) != 0) {
        *out_mask &= ~RenderState_linearFiltering;
    }
    if ((createFlags & 4) != 0) {
        *out_mask &= ~RenderState_useLightSplat;
    }
}

void dk2::AtlasMeshGroup_performDrawCall() {
    AtlasMeshGroup *pGroup = g_AtlasMeshGroup_current;
    if ((pGroup->renderFlags_x2[0] & RenderState_use3DPipeline) != 0) {
        g_totalVerticesCount += dk2::g_DrawTriangleList_verticesCount;
        g_totalTrianglesCount += dk2::g_DrawTriangleList_trianglesCount;
        return;
    }
    if (!dk2::g_DrawTriangleList_verticesCount) return;
    if(patch::opengl_patch::enabled) {
        int stageIdx = 0;
        for(signed int i = 0; i < pGroup->texStagesCount; ++i) {
            patch::opengl_patch::drawCall(
                    pGroup->renderFlags_x2[i],  // render state
                    &pGroup->holders[stageIdx], pGroup->numTextureSamplers_x2[i],  // textures
                    g_vertices[i].MyD3D3Vertices, dk2::g_MyD3D3Vertex_size, dk2::g_DrawTriangleList_verticesCount,  // vertices
                    g_DrawTriangleList_lpwIndices, dk2::g_DrawTriangleList_trianglesCount  // indices
            );
            stageIdx += pGroup->numTextureSamplers_x2[i];
        }
        return;
    }
    int stageIdx = 0;
    for(signed int texStageIdx = 0; texStageIdx < pGroup->texStagesCount; ++texStageIdx) {
        for(signed int stage = 0; stage < pGroup->numTextureSamplers_x2[texStageIdx]; ++stage) {
            renderer_bindStageTexture(pGroup->holders[stageIdx], stage);
            ++stageIdx;
        }
        if ((MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
            mgsr_setDrawFun(pGroup->renderFlags_x2[texStageIdx]);
            for (int i = 0; i < dk2::g_DrawTriangleList_trianglesCount; ++i) {
                Idx3us &vertIndexPos = dk2::g_DrawTriangleList_lpwIndices[i];
                mgsr_drawTriangle24_impl5(
                        (__m64 *) &dk2::g_vertices[texStageIdx].vertices18x2[vertIndexPos.i],
                        (__m64 *) &dk2::g_vertices[texStageIdx].vertices18x2[vertIndexPos.j],
                        (__m64 *) &dk2::g_vertices[texStageIdx].vertices18x2[vertIndexPos.k]
                );
            }
            _m_empty();
        } else {
            MyDirectDraw_prepareTexture(pGroup->renderFlags_x2[texStageIdx]);
            MyDirectDraw_DrawTriangleList(texStageIdx, dk2::g_DrawTriangleList_trianglesCount, dk2::g_DrawTriangleList_verticesCount);
        }
    }
}


namespace dk2 {

    void MeshGroup_init(AtlasMeshGroup *meshGroup, SceneObject2E *sceneObj,
                        RenderStageTex **atlases) {
        for (int i = 0; i < sceneObj->surfhCount; ++i) {
            meshGroup->holders[i] = atlases[i];
        }
        for (int i = 0; i < sceneObj->texStagesCount; ++i) {
            uint32_t renderFlags = sceneObj->renderFlags_x2[i];
            {  // patch
                static VisualBool alphaBlendOne("renderFlags.alphaBlendOne");
                if(alphaBlendOne) {
                    renderFlags &= (RenderState_alphaBlendInvSrc | RenderState_alphaBlendSrc | RenderState_alphaBlendOne);
                    renderFlags |= RenderState_alphaBlendOne;
                }
                static VisualBool alphaBlendSrc("renderFlags.alphaBlendSrc");
                if(alphaBlendSrc) {
                    renderFlags &= (RenderState_alphaBlendInvSrc | RenderState_alphaBlendSrc | RenderState_alphaBlendOne);
                    renderFlags |= RenderState_alphaBlendSrc;
                }
                static VisualBool alphaBlendInvSrc("renderFlags.alphaBlendInvSrc");
                if(alphaBlendInvSrc) {
                    renderFlags &= (RenderState_alphaBlendInvSrc | RenderState_alphaBlendSrc | RenderState_alphaBlendOne);
                    renderFlags |= RenderState_alphaBlendInvSrc;
                }
                static VisualBool use3DPipeline("renderFlags.use3DPipeline");
                if(use3DPipeline) renderFlags &= ~RenderState_use3DPipeline;
                static VisualBool linearFiltering("renderFlags.linearFiltering");
                if(linearFiltering) renderFlags |= RenderState_linearFiltering;
            }
            meshGroup->renderFlags_x2[i] = renderFlags;
            meshGroup->numTextureSamplers_x2[i] = sceneObj->numTextureSamplers_x2[i];
        }
        meshGroup->surfhCount = sceneObj->surfhCount;
        meshGroup->zeroOrM1 = sceneObj->zeroOrM1;
        meshGroup->texStagesCount = sceneObj->texStagesCount;
        meshGroup->totalTriangles = 0;
        meshGroup->totalVertices = 0;
        meshGroup->sceneObjects_first = NULL;
    }
    bool sub2_sameFlags(SceneObject2E *cur, AtlasMeshGroup *meshGroup) {
        for (int j = 0; j < cur->texStagesCount; ++j) {
            if (meshGroup->renderFlags_x2[j] != cur->renderFlags_x2[j]) return false;
        }
        return true;
    }
    bool sub3_sameStageTexs(SceneObject2E *sceneObj, RenderStageTex **stageTexs, AtlasMeshGroup *meshGroup) {
        if (meshGroup->surfhCount != sceneObj->surfhCount) return false;
        for (int j = 1; j < sceneObj->surfhCount; ++j) {
            if (meshGroup->holders[j] != stageTexs[j]) return false;
        }
        return true;
    }

}

void dk2::__probablySortSurfListX3_593F20() {
    if (pSurfHashList2_2)
        pSurfHashList2_2->_probablySort();
    if (g_pSurfHashList2)
        g_pSurfHashList2->_probablySort();
    if (g_pSurfHashList)
        g_pSurfHashList->_probablySort();
}

void dk2::group_SceneObject2E_by_AtlasMeshGroup_andDraw() {
    __probablySortSurfListX3_593F20();
    AtlasMeshGroup *lastGroup = NULL;
    if (SceneObject2E_count >= AtlasMeshGroupList_instance.maxCount) {
        AtlasMeshGroupList_instance.enlarge(SceneObject2E_count);
    }
    int groupIdx = 0;
    RenderStageTex *curAtlases[4];
    for (int objIdx = 0; objIdx < SceneObject2E_count; ++objIdx) {
        SceneObject2E *sceneObj = &SceneObject2EList_instance.arr[objIdx];
        for (int stage = 0; stage < sceneObj->surfhCount; ++stage) {
            curAtlases[stage] = sceneObj->surfh_x4[stage]->curReduction->holder_parent;
        }
        // search for MeshGroup with same renderFlags and atlases
        AtlasMeshGroup *meshGroup = curAtlases[0]->meshGroup_first;
        for (; meshGroup; meshGroup = meshGroup->byAtlas_next) {
            if (meshGroup->texStagesCount != sceneObj->texStagesCount) continue;
            if (meshGroup->zeroOrM1 != sceneObj->zeroOrM1) continue;
            if(!sub2_sameFlags(sceneObj, meshGroup)) continue;
            if(!sub3_sameStageTexs(sceneObj, curAtlases, meshGroup)) {
                throw std::exception("should not happen");
                continue;
            }
            break;
        }
        if (meshGroup) {
            // dk2 does not want to render > 256 triangles in one draw call
            if (sceneObj->lod__triangleCount + meshGroup->totalTriangles > 256)
                meshGroup = NULL;
        }
        if (!meshGroup) {
            // fixme: check if groupIdx < ToDrawList_instance.size
            // create new mesh group and add to list
            meshGroup = &AtlasMeshGroupList_instance.AtlasMeshGroup_arr[groupIdx];
            MeshGroup_init(meshGroup, sceneObj, curAtlases);
            {  // register in atlas list
                RenderStageTex *atlas = curAtlases[0];
                meshGroup->byAtlas_next = atlas->meshGroup_first;
                atlas->meshGroup_first = meshGroup;
            }
            {  // register in render list
                meshGroup->byRender_next = lastGroup;
                lastGroup = meshGroup;
            }
            ++groupIdx;
        }
        {  // add sceneObj to meshGroup
            sceneObj->next = meshGroup->sceneObjects_first;
            meshGroup->sceneObjects_first = sceneObj;
        }
        meshGroup->totalTriangles += sceneObj->lod__triangleCount;
        meshGroup->totalVertices += sceneObj->numVertsEx;
    }
    for (AtlasMeshGroup *cur = lastGroup; cur; cur = cur->byRender_next) {
        selectAtlasMeshGroup(cur);
        for (SceneObject2E *sceneObj = cur->sceneObjects_first; sceneObj; sceneObj = sceneObj->next) {
            char kind[64];
            {  // patch
                CEnginePrimitiveBase_format(sceneObj->mesh, kind, sizeof(kind));
            }

            sceneObj->mesh->v___addRenderObj((uint16_t) sceneObj->f2C_, sceneObj);

            {  // patch
                if(sceneObj->mesh->getVtbl() == dk2::CEngineDynamicHeightField::vftable) {
                    auto *dyhf = (dk2::CEngineDynamicHeightField *) sceneObj->mesh;
                    int c1 = dk2::g_DrawTriangleList_trianglesCount;
                    auto *ids = g_DrawTriangleList_lpwIndices;

                    VerticesData &verts0 = g_vertices[0];
                    auto *tex1 = (dk2::CEngineDDSurface *) cur->holders[0]->surf;
//                    auto *buf1 = (uint8_t *) tex1->v_lockBuf();
                    // RenderState_bumpMapLuminance
                    // RenderState_linearFiltering | RenderState_use3DPipeline | RenderState_zEnable
                    // RenderState_useLightSplat | RenderState_alphaBlendSrc
                    // RenderState_fl2
                    uint32_t fl1 = cur->renderFlags_x2[0];  // 10762

                    for(int i = 0; i < dk2::g_DrawTriangleList_verticesCount; i++) {
                        {
                            auto *v1 = (MyD3D3Vertex *) ((char *) verts0.MyD3D3Vertices + g_MyD3D3Vertex_size * i);
                            Pos2i tp1{(int) (v1->tex[0].v * tex1->height), (int) (v1->tex[0].u * tex1->width)};
//                            dump_bgra32(
//                                    buf1 + tex1->pitch * (tp1.y - 16) + (tp1.x - 16) * 4,
//                                    32, 32, tex1->pitch, "test1", 16
//                            );
                        }
                    }
                    GetTickCount();
//                    tex1->v_unlockBuf(0);

//                    dump(*tex1, "test");
                }
                if(cur->texStagesCount > 1) {
                    if(sceneObj->mesh->getVtbl() == dk2::CEngineStaticMesh::vftable) {
                        auto *st = (dk2::CEngineStaticMesh *) sceneObj->mesh;
                    }

                    int c1 = dk2::g_DrawTriangleList_trianglesCount;
                    VerticesData &verts0 = g_vertices[0];
                    auto *tex1 = (dk2::CEngineDDSurface *) cur->holders[0]->surf;
//                    auto *buf1 = (uint8_t *) tex1->v_lockBuf();
                    // RenderFlags_zEnable | RenderFlags_linearFiltering
                    // RenderFlags_zWriteEnable | RenderFlags_useLightSplat
                    uint32_t fl1 = cur->renderFlags_x2[0];  // 5C0

                    VerticesData &verts1 = g_vertices[1];
                    auto *tex2 = (dk2::CEngineDDSurface *) cur->holders[1]->surf;
//                    auto *buf2 = (uint8_t *) tex2->v_lockBuf();
                    // RenderFlags_zEnable | RenderFlags_linearFiltering
                    // RenderFlags_alphaBlendOne
                    uint32_t fl2 = cur->renderFlags_x2[1];  // 501

                    std::stringstream ss;
                    for(int i = 0; i < dk2::g_DrawTriangleList_verticesCount; i++) {
                        {
                            auto *v1 = (MyD3D3Vertex *) ((char *) verts0.MyD3D3Vertices + g_MyD3D3Vertex_size * i);
                            Pos2i tp1 {(int) (v1->tex[0].v * tex1->height), (int) (v1->tex[0].u * tex1->width)};
//                            dump_bgra32(
//                                    buf1 + tex1->pitch * (tp1.y - 16) + (tp1.x - 16) * 4,
//                                    32, 32, tex1->pitch, "test1", 16
//                            );
                        }
                        {
                            auto *v2 = (MyD3D3Vertex *) ((char *) verts1.MyD3D3Vertices + g_MyD3D3Vertex_size * i);
                            Pos2i tp2 {(int) (v2->tex[0].v * tex2->height), (int) (v2->tex[0].u * tex2->width)};
//                            dump_bgra32(
//                                    buf2 + tex2->pitch * (tp2.y - 16) + (tp2.x - 16) * 4,
//                                    32, 32, tex2->pitch, "test2", 16
//                            );
                            char tmp[32];
                            snprintf(tmp, sizeof(tmp), "{%d,%d}", tp2.x, tp2.y);
//                            snprintf(tmp, sizeof(tmp), "{%.2f,%.2f}", v2->tex[0].u, v2->tex[0].v);
                            ss << tmp << " ";
                        }
                    }
//                    dump(*tex2, ss.str().c_str());
                    auto *ids = g_DrawTriangleList_lpwIndices;
//                    tex1->v_unlockBuf(0);
//                    tex2->v_unlockBuf(0);
                }
            }
            {  // patch
                if(cur->numTextureSamplers_x2[0] > 1) {
//                    for (int i = 0; i < cur->numTextureSamplers_x2[0]; ++i) {
//                        dump(*cur->holders[i]->surf, "surf");
//                    }
                    GetTickCount();
                }
            }
        }
        AtlasMeshGroup_performDrawCall();
        cur->holders[0]->meshGroup_first = NULL;
    }
    SceneObject2E_count = 0;
}

namespace dk2 {

    void g_MyD3D3Vertex_buf_extendBuf(unsigned int requiredSize) {
        if (g_MyD3D3Vertex_maxCount >= (int) requiredSize) return;
        void *newBuf = MyHeap_alloc(g_MyD3D3Vertex_size * (g_MyD3D3Vertex_maxCount + 512));
        // copy old
        memcpy(newBuf, g_MyD3D3Vertex_buf, g_MyD3D3Vertex_maxCount * g_MyD3D3Vertex_size);
        // release old
        MyHeap_free(g_MyD3D3Vertex_buf);
        // finalize
        g_MyD3D3Vertex_buf = newBuf;
        g_MyD3D3Vertex_maxCount += 512;
    }
    void g_GlobalToLocal_indicesMap_extendBuf(unsigned int requiredSize) {
        if (g_GlobalToLocal_indicesMap.maxCount > requiredSize) return;
        unsigned int newMaxCount = g_GlobalToLocal_indicesMap.maxCount;
        do {
            newMaxCount += g_GlobalToLocal_indicesMap.expandCount;
        } while (newMaxCount <= requiredSize);
        WORD *newIndices = (WORD *) MyHeap_alloc(sizeof(WORD) * newMaxCount);
        // copy old
        if (g_GlobalToLocal_indicesMap.maxCount) memcpy(newIndices, g_GlobalToLocal_indicesMap.buf, sizeof(WORD) * g_GlobalToLocal_indicesMap.maxCount);
        // fill empty new
        for (unsigned int i = g_GlobalToLocal_indicesMap.maxCount; i < newMaxCount; ++i) newIndices[i] = -1;
        // release old
        MyHeap_free(g_GlobalToLocal_indicesMap.buf);
        // finalize
        g_GlobalToLocal_indicesMap.buf = newIndices;
        g_GlobalToLocal_indicesMap.maxCount = newMaxCount;
    }
    void g_MyEntryBuf_Triangle24_instance_extendBuf(unsigned int requiredSize) {
        if (g_MyEntryBuf_Triangle24_instance.maxCount > requiredSize) return;
        unsigned int v12_maxCount = g_MyEntryBuf_Triangle24_instance.maxCount;
        do {
            v12_maxCount += g_MyEntryBuf_Triangle24_instance.expandCount;
        } while (v12_maxCount <= requiredSize);
        Triangle24 *v13_triangles = (Triangle24 *) MyHeap_alloc(sizeof(Triangle24) * v12_maxCount);
        // copy old
        if (g_MyEntryBuf_Triangle24_instance.maxCount)
            memcpy(
                    v13_triangles,
                    g_MyEntryBuf_Triangle24_instance.buf,
                    sizeof(Triangle24) * g_MyEntryBuf_Triangle24_instance.maxCount
            );
        // release old
        MyHeap_free(g_MyEntryBuf_Triangle24_instance.buf);
        // finalize
        g_MyEntryBuf_Triangle24_instance.buf = v13_triangles;
        g_MyEntryBuf_Triangle24_instance.maxCount = v12_maxCount;
    }

}

void __cdecl dk2::selectAtlasMeshGroup(AtlasMeshGroup *meshGroup) {
    g_AtlasMeshGroup_current = meshGroup;
    g_DrawTriangleList_verticesCount = 0;
    g_DrawTriangleList_trianglesCount = 0;
    unsigned int totalTrianglesCount = g_totalTrianglesCount + 4 * meshGroup->totalTriangles;
    unsigned int totalVerticesCount = g_totalVerticesCount + 4 * meshGroup->totalVertices;
    if ((MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        if ((meshGroup->renderFlags_x2[0] & RenderState_use3DPipeline) != 0) {
            if (totalVerticesCount >= g_MyEntryBuf_Vertex18_instance.maxCount)
                g_MyEntryBuf_Vertex18_instance.resize(totalVerticesCount);
            g_vertices[0].vertices18hx2_pos = &g_MyEntryBuf_Vertex18_instance.buf[g_totalVerticesCount];
            if (totalTrianglesCount >= g_MyEntryBuf_Triangle24_instance.maxCount)
                g_MyEntryBuf_Triangle24_instance.resize(totalTrianglesCount);
        } else {
            for (int i = 0; i < 2; ++i) {
                g_vertices[i].vertices18hx2_pos = g_vertices[i].vertices18x2;
            }
            g_CEnginePrimitiveBase_addObj_lpwIndices = (Idx3us *) g_DrawTriangleList_lpwIndices;
        }
    } else {
        if ((meshGroup->renderFlags_x2[0] & RenderState_use3DPipeline) != 0) {
            g_MyD3D3Vertex_buf_extendBuf(totalVerticesCount);  // MyD3D3Vertex
            g_GlobalToLocal_indicesMap_extendBuf(totalVerticesCount);  // indices
            g_vertices[0].MyD3D3Vertex_pos = (MyD3D3Vertex *) ((char *) g_MyD3D3Vertex_buf + g_totalVerticesCount * g_MyD3D3Vertex_size);
            g_MyEntryBuf_Triangle24_instance_extendBuf(totalVerticesCount);  // Triangle24
        } else {
            for (int i = 0; i < 2; ++i) {
                g_vertices[i].MyD3D3Vertex_pos = g_vertices[i].MyD3D3Vertices;
            }
            g_CEnginePrimitiveBase_addObj_lpwIndices = (Idx3us *) g_DrawTriangleList_lpwIndices;
        }
    }
}


void __cdecl dk2::renderer_bindStageTexture(RenderStageTex *stageTex, uint32_t stage) {
    if(!patch::opengl_patch::enabled) {
        if(gog::RenderStageTex_setTexture_patch::isEnabled()) {
            if(!stageTex) return;
        }
    }
    if ( (MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0 ) {
        mgsr_lockedBuf_dw256x256 = (uint32_t *) stageTex->surf->v_lockBuf();
    } else {
        CEngineDDSurface *ddsurf = (CEngineDDSurface *) stageTex->surf;
        if(patch::opengl_patch::enabled) {
            if(!patch::opengl_patch::bindTex(stage, *ddsurf)) {
                g_sc_isCurDdSurfLost = 1;
            }
        } else {
            MyDirectDraw_instance_devTexture.d3d3_halDevice->SetTexture(stage, ddsurf->devTex);
            if (ddsurf->ddSurf->IsLost()) g_sc_isCurDdSurfLost = 1;
        }
    }
}


void __cdecl dk2::updateLoadingScreenProgress(int arg0, int a1_pstatus) {
    if (a1_pstatus) {
        CWorld_instance.showLoadingScreen();
        if (CWorld_instance.loadingScreen_present) {
            MyDdSurface_release(&a1_pstatus, &CWorld_instance.loadingScreen_surf.dd_surf);
            CWorld_instance.loadingScreen_present = 0;
        }

        if (MyWindow_instance.getSurf_lock()) {
            AABB a1;
            a1.minX = 23 * MyWindow_instance.dwWidth / 640;
            a1.minY = 445 * MyWindow_instance.dwHeight / 480;
            a1.maxY = 457 * MyWindow_instance.dwHeight / 480;
            a1.maxX = a1.minX + arg0 * (188 * MyWindow_instance.dwWidth / 640 - a1.minX) / 33;
            Bgraf color;
            *(DWORD *) &color = 0xFFFF6E00;
            color.fill = 0;
            static_MyNBitTexture_f4(&a1, color);
            MyWindow_instance.getSurf_unlock();
            MyWindow_instance.prepareScreen();
        }
    }
}

