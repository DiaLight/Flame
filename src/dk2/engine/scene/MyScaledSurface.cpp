//
// Created by DiaLight on 10/9/2025.
//

#include "dk2/MyScaledSurface.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/MySurfaceWrapper.h"
#include "dk2/MyStringHashMap_MyCESurfHandle_entry.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/math/color.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "RenderState_flags.h"


dk2::MyScaledSurface *dk2::MyScaledSurface::constructor(MyDblNamedSurface *surfdn_, int idx) {
    MySurfaceWrapper surfw;
    this->idx = idx;
    this->color21 = surfdn_->color50 * 255.0;
    this->surfh = NULL;
    this->colorMult = surfdn_->colorMult;
    this->nextPrescaledItem = NULL;
    this->renderFlags = RenderState_zEnable | RenderState_zWriteEnable | RenderState_useLightSplat;
    this->flags = surfdn_->flags;
    if ((this->flags & 0x100) == 0) {
        this->renderFlags |= RenderState_linearFiltering;
    }
    if ((this->flags & 0x10) != 0) {
        this->renderFlags &= ~(RenderState_useLightSplat | RenderState_zWriteEnable);
        this->renderFlags |= RenderState_use3DPipeline | RenderState_alphaBlendOne;
        this->color21.r = 255.0;
        this->color21.g = 255.0;
        this->color21.b = 255.0;
    }
    if ((this->flags & 1) != 0) {
        this->renderFlags &= ~RenderState_zWriteEnable;
        this->renderFlags |= RenderState_use3DPipeline | RenderState_alphaBlendSrc | RenderState_fl2;
    }
    if ((this->flags & 0x400) != 0) {
        this->renderFlags &= ~RenderState_zWriteEnable;
        this->renderFlags |= RenderState_use3DPipeline | RenderState_alphaBlendInvSrc;
    }
    if ((this->flags & 0xE) != 0) {
        this->renderFlags &= ~RenderState_zWriteEnable;
        this->renderFlags |= RenderState_use3DPipeline | RenderState_alphaBlendSrc;
    }
    if ((this->flags & 0x40) != 0) {
        this->renderFlags &= ~RenderState_useLightSplat;
    }
    if ((this->flags & 0x200) != 0) {
        this->renderFlags |= RenderState_fl800;
        surfw.constructor(1, surfdn_->name, 0);
        int i = MySurfaceWrapper_createPrescaled(&surfw, 0);
        this->surfh = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
    }
    this->prob_height = surfdn_->init1__height;
    this->prob_width = surfdn_->init1__width;
    this->scaledSurfArr = (MyCESurfScale*) MyHeap_alloc(sizeof(MyCESurfScale) * this->prob_height * this->prob_width);
    if ((this->flags & 0x800) != 0) {
        this->renderFlags |= RenderState_fl2000;
        surfw.withData(5, *surfdn_->pNames, surfdn_->blWidth, surfdn_->blHeight);
        int i = MySurfaceWrapper_createPrescaled(&surfw, 1);
        this->scaledSurfArr[0].surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
        return this;
    }
    if ((this->flags & 0x4000) != 0) {
        for (int x = 0; x < this->prob_width; ++x) {
            for (int y = 0; y < this->prob_height; ++y) {
                int flags__ = (this->flags & 0x1000 | 0x800u) >> 11;
                if ((this->flags & 0x2000) != 0)
                    flags__ = flags__ | 8;
                surfw.constructor(flags__, surfdn_->pNames[y], x);
                int i = MySurfaceWrapper_createPrescaled(&surfw, 0);
                if (i < 0) {
                    int v21_idx = EngineTextureWhite_a31x400_idx;
                    if (EngineTextureWhite_a31x400_idx < 0 || EngineTextureWhite_a31x400_idx >= MyEntryBuf_MyScaledSurface_instance.count) {
                        MyWindow_log_printf(&MyWindow_instance, "Invalid Material\n");
                    }
                    MyScaledSurface* v22_surf = MyEntryBuf_MyScaledSurface_instance.buf[v21_idx];
                    this->scaledSurfArr[y + this->prob_height * x].surfScaledArr[0] = v22_surf->scaledSurfArr->surfScaledArr[0];
                } else {
                    this->scaledSurfArr[y + this->prob_height * x].surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
                }
            }
        }
        return this;
    }
    if ((this->flags & 0x8000) != 0) {
        surfw.sub_590B70(0x10, *surfdn_->pNames, &surfdn_->surf);
        int i = MySurfaceWrapper_createPrescaled(&surfw, 1);
        this->scaledSurfArr[0].surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
        return this;
    }
    surfw.withData(0, *surfdn_->pNames, surfdn_->blWidth, surfdn_->blHeight);
    int i = MySurfaceWrapper_createPrescaled(&surfw, 1);
    this->scaledSurfArr[0].surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
    return this;
}


