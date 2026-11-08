//
// Created by DiaLight on 1/22/2026.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/RenderStageTex.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/CEngineSurfaceBase.h"
#include "dk2/CEngineDDSurface.h"
#include "dk2/CEngineSurface.h"
#include "dk2/Vertex18.h"
#include "MyDirectDraw_flags.h"

dk2::RenderStageTex *__cdecl dk2::RenderStageTex_create(uint32_t size, MyCEngineSurfDesc *desc, int useVideoMMemory) {
    CEngineSurfaceBase *surfb;
    if (useVideoMMemory) {
        CEngineDDSurface *surf = (CEngineDDSurface *) MyHeap_alloc(sizeof(CEngineDDSurface));
        if (surf) {
            surf->constructor(size, size, desc, 1);
            if (surf->createError) {
                if (surf)
                    surf->v_scalar_destructor(1u);
                return NULL;
            }
        } else {
            surf = NULL;
        }
        surfb = surf;
    } else {
        static_assert(sizeof(CEngineSurface) == 24);
        CEngineSurface *surf = (CEngineSurface *) MyHeap_alloc(sizeof(CEngineSurface));
        if (surf) {
            surf->fC_desc = desc;
            *(void **) surf = CEngineSurfaceBase::vftable;
            surf->width = size;
            surf->height = size;
            surf->pitch = desc->bytesPerPixel * size;
            *(void **) surf = CEngineSurface::vftable;
            surf->pixels = MyHeap_alloc(desc->bytesPerPixel * size * size);
        } else {
            surf = NULL;
        }
        surfb = surf;
    }
    RenderStageTex *result = (RenderStageTex *) MyHeap_alloc(sizeof(RenderStageTex));
    if (result) {
        result->useVideoMemory = useVideoMMemory;
        result->surf = surfb;
        result->prev_ = NULL;
        result->surfh_first = NULL;
        result->meshGroup_first = NULL;
        result->hashItem_link = 0;
    } else {
        result = NULL;
    }
    result->_1divSize = 1.0 / (double) (int) size;
    return result;
}

int dk2::RenderStageTex::calcWeight() {
    int weight = 0;
    for (MyCESurfHandle *cur = this->surfh_first; cur; cur = cur->nextByHolder) {
        int bufSize = cur->surfWidth8 * cur->surfHeight8;
        if ((cur->reductionLevel_andFlags & 0x10) != 0) {
            weight += 4 * bufSize;
        } else {
            int ticks = SurfHashList_sortTick - cur->sortTick;
            if (ticks <= 0) {
                weight += bufSize;
            } else {
                weight += bufSize * (2 / (ticks + 1) + 1);
            }
        }
    }
    return weight;
}

void dk2::RenderStageTex::drawSpecial_128x128(float x, float y) {
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        this->drawSpecial_128x128_mgsr(x, y);
    } else {
        DWORD alphablendEnable;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, &alphablendEnable);
        DWORD textureHandle;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, &textureHandle);
        DWORD zFunc;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_ZFUNC, &zFunc);

        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ZFUNC, 8);
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 0);
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
            mgsr_lockedBuf_dw256x256 = (uint32_t *) this->surf->v_lockBuf();
        } else {
            CEngineDDSurface *fC_ddsurf = (CEngineDDSurface *) this->surf;
            MyDirectDraw_instance_devTexture.d3d3_halDevice->SetTexture(0, fC_ddsurf->devTex);
            if (fC_ddsurf->ddSurf->IsLost())
                g_sc_isCurDdSurfLost = 1;
        }
        D3DTLVERTEX vertices[4];
        vertices[0].sx = x;
        vertices[0].sy = y;
        vertices[0].tu = 0.0;
        vertices[0].tv = 0.0;

        vertices[1].sx = x - -128.0;
        vertices[1].sy = y;
        vertices[1].tu = 1.0;
        vertices[1].tv = 0.0;

        vertices[2].sx = vertices[1].sx;
        D3DVALUE maxX = y - -128.0;
        vertices[2].tu = 1.0;
        vertices[2].tv = 1.0;
        vertices[2].sy = maxX;

        vertices[3].sx = x;
        vertices[3].tu = 0.0;
        vertices[3].sy = maxX;
        vertices[3].tv = 1.0;
        for (int i = 0; i < 4; ++i) {
            auto &p_rhw = vertices[i];
            p_rhw.sz = 0.0;
            p_rhw.rhw = 1.0;
            p_rhw.color = -1;
            p_rhw.specular = 0;
        }
        WORD indices1[6] {
            0, 1, 2,
            0, 2, 3
        };
        MyDirectDraw_instance_devTexture.d3d3_halDevice->DrawIndexedPrimitive(
                D3DPT_TRIANGLELIST,
                0x1C4,  // dwVertexTypeDesc: D3DFVF_TLVERTEX  sizeof(D3DTLVERTEX) == (8 * 4)
                vertices, 4,
                indices1, 6,
                8);

        DWORD fillMode;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_FILLMODE, &fillMode);

        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_FILLMODE, 2);
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, 0);

        WORD indices2[8] {
            0, 1,
            1, 2,
            2, 3,
            3, 0
        };
        for (int i = 0; i < 4; ++i) {  // why 4 times draw same lines?
            vertices[0].sx = vertices[0].sx - 1.0;
            vertices[0].sy = vertices[0].sy - 1.0;
            vertices[1].sx = vertices[1].sx - -1.0;
            vertices[1].sy = vertices[1].sy - 1.0;
            vertices[2].sx = vertices[2].sx - -1.0;
            vertices[2].sy = vertices[2].sy - -1.0;
            vertices[3].sx = vertices[3].sx - 1.0;
            vertices[3].sy = vertices[3].sy - -1.0;
            MyDirectDraw_instance_devTexture.d3d3_halDevice->DrawIndexedPrimitive(
                    D3DPT_LINELIST, 0x1C4,
                    vertices, 4,
                    indices2, 8,
                    8);
        }

        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ZFUNC, zFunc);
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_FILLMODE, fillMode);
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, textureHandle);
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, alphablendEnable);
    }
}

int dk2::RenderStageTex::drawSpecial_128x128_mgsr(float x, float y) {
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        mgsr_lockedBuf_dw256x256 = (uint32_t *) this->surf->v_lockBuf();
    } else {
        CEngineDDSurface *fC_surf = (CEngineDDSurface *) this->surf;
        MyDirectDraw_instance_devTexture.d3d3_halDevice->SetTexture(0, fC_surf->devTex);
        if (fC_surf->ddSurf->IsLost())
            g_sc_isCurDdSurfLost = 1;
    }
    double f16_x = x * 16.0;
    float f16_y = y * 16.0;

    Vertex18 h[4];

    h[0].x = (__int64) f16_x;
    h[0].y = (__int64) f16_y;
    h[0].texU = 0;
    h[0].texV = 0;

    h[1].x = (__int64) (f16_x - -2048.0);
    h[1].y = h[0].y;
    h[1].texU = 0x7FFF;
    h[1].texV = 0;

    h[2].x = h[1].x;
    h[2].y = (__int64) (f16_y - -2048.0);
    h[2].texU = 0x7FFF;
    h[2].texV = 0x7FFF;

    h[3].x = h[0].x;
    h[3].y = h[2].y;
    h[3].texU = 0;
    h[3].texV = 0x7FFF;

    for (int i = 0; i < 4; ++i) {
        h[i].multi = -1;
    }

    mgsr_pDrawFun = mgsr_drawFuns[32];
    mgsr_drawTriangle24_impl5((__m64 *) &h[0], (__m64 *) &h[1], (__m64 *) &h[2]);
    int result = mgsr_drawTriangle24_impl5((__m64 *) &h[0], (__m64 *) &h[2], (__m64 *) &h[3]);
    _m_empty();
    return result;
}


