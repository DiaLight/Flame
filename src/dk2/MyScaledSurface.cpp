//
// Created by DiaLight on 10/9/2025.
//

#include "dk2/MyScaledSurface.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/MySurfaceWrapper.h"
#include "dk2/MyStringHashMap_MyCESurfHandle_entry.h"
#include "dk2/MyCESurfScale.h"
#include "dk2_functions.h"
#include "dk2_globals.h"


dk2::MyScaledSurface *dk2::MyScaledSurface::constructor(MyDblNamedSurface *surfdn_, int idx) {
    MySurfaceWrapper surfw;
    this->idx = idx;
    this->vec = *(Vec3f*) &surfdn_->initx;
    this->vec.x = this->vec.x * 255.0;
    this->vec.y = this->vec.y * 255.0;
    this->vec.z = this->vec.z * 255.0;
    this->surfh = NULL;
    this->f1D = surfdn_->init0;
    this->nextPrescaledItem = NULL;
    this->drawFlags = 0x1C0;
    this->flags = surfdn_->flags;
    if ((this->flags & 0x100) == 0) {
        this->drawFlags = 0x5C0;
    }
    if ((this->flags & 0x10) != 0) {
        this->drawFlags &= ~0xC0;
        this->drawFlags |= 0x201;
        this->vec.x = 255.0;
        this->vec.y = 255.0;
        this->vec.z = 255.0;
    }
    if ((this->flags & 1) != 0) {
        this->drawFlags &= ~0x80;
        this->drawFlags |= 0x222;
    }
    if ((this->flags & 0x400) != 0) {
        this->drawFlags &= ~0x80;
        this->drawFlags |= 0x1200u;
    }
    if ((this->flags & 0xE) != 0) {
        this->drawFlags &= ~0x80;
        this->drawFlags |= 0x220;
    }
    if ((this->flags & 0x40) != 0) {
        this->drawFlags &= ~0x40u;
    }
    if ((this->flags & 0x200) != 0) {
        this->drawFlags |= 0x800u;
        surfw.constructor(1, surfdn_->name, 0);
        int i = MySurfaceWrapper_createPrescaled(&surfw, 0);
        this->surfh = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
    }
    this->prob_height = surfdn_->init1__height;
    this->prob_width = surfdn_->init1__width;
    this->scaledSurfArr = (MyCESurfScale*) MyHeap_alloc(16 * this->prob_height * surfdn_->init1__width);
    if ((this->flags & 0x800) != 0) {
        this->drawFlags |= 0x2000u;
        surfw.withData(5, *surfdn_->pNames, surfdn_->blWidth, surfdn_->blHeight);
        int i = MySurfaceWrapper_createPrescaled(&surfw, 1);
        this->scaledSurfArr->surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
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
                        MyGame_debugMsg(&MyGame_instance, "Invalid Material\n");
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
        this->scaledSurfArr->surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
        return this;
    }
    surfw.withData(0, *surfdn_->pNames, surfdn_->blWidth, surfdn_->blHeight);
    int i = MySurfaceWrapper_createPrescaled(&surfw, 1);
    this->scaledSurfArr->surfScaledArr[0] = MyStringHashMap_MyCESurfHandle_instance.entries.buf[i].value;
    return this;
}


