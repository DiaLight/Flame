//
// Created by DiaLight on 6/13/2026.
//

#include "dk2/CEngineSurfaceBase.h"
#include "dk2/CEngineSurface.h"
#include "dk2/MyCEngineSurfDesc.h"

int dk2::CEngineSurfaceBase::paintSurf(CEngineSurface *surf, int xo, int yo) {
    int result = this->v_paintSurf(surf, xo, yo);
    if (result) return result;
    result = surf->v_copySurf(this, xo, yo);
    if (result) return result;
    char *srcBuf = (char *) surf->v_lockBuf();
    char *dstBuf = (char *) this->v_lockBuf();
    int bpp = this->fC_desc->bytesPerPixel;
    int xoffs = xo * bpp;
    for (int y = 0; y < surf->height; ++y) {
        memcpy(
                &dstBuf[this->pitch * (yo + y) + xoffs],
                &srcBuf[surf->pitch * y],
                surf->width * bpp
        );
    }
    this->v_unlockBuf(dstBuf);
    return surf->v_unlockBuf(srcBuf);
}

int dk2::CEngineSurfaceBase::fill(__int16 pix) {
    char *pixBuf = (char *) this->v_lockBuf();
    char *line = (char *) pixBuf;
    for (int y = 0; y < this->height; ++y) {
        for (int x = 0; x < this->width; ++x) {
            ((WORD *) line)[x] = pix;
        }
        line += this->pitch;
    }
    return this->v_unlockBuf(pixBuf);
}
