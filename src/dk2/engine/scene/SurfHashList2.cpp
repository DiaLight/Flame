//
// Created by DiaLight on 1/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/SurfHashList2.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/RenderStageTex.h"
#include "dk2/CEngineSurfaceBase.h"
#include "dk2/CEngineDDSurface.h"
#include "dk2/SurfHashListItem.h"


char dk2::SurfHashList2::constructor(MyCEngineSurfDesc *a2, int a3_count, int a4_count) {
    this->surfDesc = a2;
    this->stageTex_size = 128;
    this->stageTex_count = 0;
    for (int v5_i = 0; v5_i < a4_count; ++v5_i) {
        RenderStageTex *v6_holder = RenderStageTex_create(this->stageTex_size, this->surfDesc, 1);
        if (!v6_holder) break;
        ++this->stageTex_count;
        RenderStageTex *pRenderStageTex = this->stageTex_first;
        if (pRenderStageTex)
            pRenderStageTex->next_ = v6_holder;
        v6_holder->next_ = 0;
        v6_holder->prev_ = this->stageTex_first;
        this->stageTex_first = v6_holder;
    }
    if (this->stageTex_count >= a3_count) {
        CEngineDDSurface *v15 = (CEngineDDSurface *) MyHeap_alloc(sizeof(CEngineDDSurface));
        static_assert(sizeof(CEngineDDSurface) == 36);
        CEngineDDSurface *v16;
        if (v15)
            v16 = v15->constructor(this->stageTex_size, this->stageTex_size, this->surfDesc, 0);
        else
            v16 = NULL;
        this->ddsurf = v16;
        return 1;
    } else {
        RenderStageTex *v8 = 0;
        if (this->stageTex_first) {
            RenderStageTex *f14_prev;
            do {
                f14_prev = this->stageTex_first->prev_;
                this->stageTex_first->prev_ = v8;
                v8 = this->stageTex_first;
                this->stageTex_first = f14_prev;
            } while (f14_prev);
        }
        if (v8) {
            RenderStageTex *v10;
            do {
                v10 = v8->prev_;
                if (v8) {
                    CEngineSurfaceBase *fC_surf;
                    fC_surf = v8->surf;
                    if (fC_surf)
                        fC_surf->v_scalar_destructor(1u);
                    SurfHashListItem *f18_hashItem_link = v8->hashItem_link;
                    if (f18_hashItem_link) {
                        v8->hashItem_link->free();
                        MyHeap_free(f18_hashItem_link);
                    }
                    MyHeap_free(v8);
                }
                v8 = v10;
            } while (v10);
        }
        CEngineDDSurface *fD0_ddsurf = this->ddsurf;
        if (fD0_ddsurf)
            fD0_ddsurf->v_scalar_destructor(1u);
        this->ddsurf = 0;
        return 0;
    }
}

int dk2::SurfHashList2::calcHandleCountToFitHolder() {
    int reduction = g_ReductionLevel;
    for (int v6 = 0; v6 < 4; ++v6) {
        int sz = 0;
        for (MyCESurfHandle *cur = this->surfh_first; cur; cur = cur->nextByHashList) {
            MyCESurfHandle *red = cur;
            for (int j = 0; j < reduction; ++j) {
                MyCESurfHandle *next = red->nextByReduction;
                if (!next) break;
                red = next;
            }
            sz += red->surfWidth8 * red->surfHeight8;
        }
        if (sz >= this->stageTex_size * this->stageTex_size * (this->stageTex_count - 1)) {
            ++reduction;
            continue;
        }
        return reduction;
    }
    return 4;
}

void dk2::SurfHashList2::_probablySort() {
    int handleCount = this->calcHandleCountToFitHolder();
    for (MyCESurfHandle *f4_surfh_first = this->surfh_first; f4_surfh_first; f4_surfh_first = f4_surfh_first->nextByHashList) {
        MyCESurfHandle *curReducted = f4_surfh_first;
        for (int handleLeft = handleCount;
             (handleLeft > 0 || (curReducted->reductionLevel_andFlags & 7) < MyDirectDraw_instance_devTexture.reductionLevel)
             && curReducted->nextByReduction;
             --handleLeft) {
            curReducted = curReducted->nextByReduction;
        }
        f4_surfh_first->curReduction = curReducted;
        float texUMul = curReducted->texUMul;
        curReducted->reductionLevel_andFlags |= 8;
        if (texUMul == 0.f)
            curReducted->holder_parent = NULL;
        if (!curReducted->holder_parent)
            this->deleteHolder(curReducted);
    }

    RenderStageTex *curStageTex = NULL;
    while (this->f8count) {
        int surfCount = 0;
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                for (MyCESurfHandle *i = this->arr5x5_surfh[x][y]; i; i = i->nextByHolder) ++surfCount;
            }
        }
        RenderStageTex *fD8_holder_first = this->stageTex_first;
        int v17_minValue = 0x10000;
        RenderStageTex *v16_minValueItem = this->stageTex_first;
        if (fD8_holder_first) {
            while (true) {
                int v18_value = fD8_holder_first->calcWeight();
                if (!v18_value) break;
                if (v18_value < v17_minValue) {
                    v17_minValue = v18_value;
                    v16_minValueItem = fD8_holder_first;
                }
                fD8_holder_first = fD8_holder_first->prev_;
                if (!fD8_holder_first) {
                    fD8_holder_first = v16_minValueItem;
                    break;
                }
            }
        } else {
            fD8_holder_first = v16_minValueItem;
        }
        if (!fD8_holder_first) {
            this->assignStageTex(curStageTex);
            break;
        }

        if (RenderStageTex *f10_prev = fD8_holder_first->next_)
            f10_prev->prev_ = fD8_holder_first->prev_;
        else
            this->stageTex_first = fD8_holder_first->prev_;

        if (RenderStageTex *f14_next = fD8_holder_first->prev_)
            f14_next->next_ = fD8_holder_first->next_;
        fD8_holder_first->next_ = NULL;
        fD8_holder_first->prev_ = NULL;
        for (MyCESurfHandle *j = fD8_holder_first->surfh_first; j; j = fD8_holder_first->surfh_first) {
            fD8_holder_first->surfh_first = j->nextByHolder;
            j->nextByHolder = NULL;
            j->holder_parent = NULL;
            if ((j->reductionLevel_andFlags & 8) != 0)
                this->deleteHolder(j);
        }
        this->sub_593880(fD8_holder_first, 0, 0, this->stageTex_size, this->stageTex_size, 3);
        if (auto *fD0_ddsurf = this->ddsurf)
            fD8_holder_first->surf->paintSurf((CEngineSurface *) fD0_ddsurf, 0, 0);
        RenderStageTex *v24 = curStageTex;
        curStageTex = fD8_holder_first;
        fD8_holder_first->prev_ = v24;
    }
    RenderStageTex *stageTex = curStageTex;
    if (stageTex) {
        while (true) {
            RenderStageTex *stageTexPrev = stageTex->prev_;
            if (RenderStageTex *first = this->stageTex_first)
                first->next_ = stageTex;
            stageTex->next_ = NULL;
            stageTex->prev_ = this->stageTex_first;
            this->stageTex_first = stageTex;
            if (!stageTexPrev)
                break;
            stageTex = stageTexPrev;
        }
    }
    if (this->surfh_first) {
        MyCESurfHandle *f10_nextByHashList;
        do {
            MyCESurfHandle *v28 = this->surfh_first;
            v28->reductionLevel_andFlags &= ~0x10u;
            v28->curReduction->reductionLevel_andFlags &= ~8u;
            f10_nextByHashList = v28->nextByHashList;
            this->surfh_first = f10_nextByHashList;
        } while (f10_nextByHashList);
    }
    ++SurfHashList_sortTick;
}

void dk2::SurfHashList2::assignStageTex(RenderStageTex *stageTex) {
    for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
            MyCESurfHandle **pHandle = &this->arr5x5_surfh[x][y];
            for (MyCESurfHandle *ceSurf = *pHandle; *pHandle; ceSurf = *pHandle) {
                ceSurf->holder_parent = stageTex;
                ceSurf->texUAdd = 0.0;
                ceSurf->texVAdd = 0.0;
                ceSurf->texUMul = 0.0;
                ceSurf->texVMul = 0.0;
                ceSurf->reductionLevel_andFlags &= ~0x20u;

                *pHandle = ceSurf->nextByHolder;
                --this->f8count;
            }
        }
    }
}
