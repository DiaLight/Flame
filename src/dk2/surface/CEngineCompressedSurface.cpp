//
// Created by DiaLight on 5/31/2026.
//

#include <exception>
#include "dk2/CEngineCompressedSurface.h"
#include "dk2/CEngineSurface.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"

int dk2::CEngineCompressedSurface::paintSurf(CEngineSurface *src, int xpos, int ypos) {
    if (xpos || ypos || !src->v_hasBuf()) return 0;
    if(patch::opengl_patch::enabled) {
        if(src->getVtbl() != CEngineSurface::vftable) {
            throw std::exception("unexpected");
        }
    }

    MyHeap_free(this->pixelBuf);
    void *srcBuf = src->v_lockBuf();
    this->bufSize = mpeg2__putpict(
            srcBuf, mpeg2__image_buf,
            this->width, this->height, src->pitch, 0, 5);
    this->pixelBuf = MyHeap_alloc(this->bufSize);
    memcpy(this->pixelBuf, mpeg2__image_buf, this->bufSize);
    src->v_unlockBuf(srcBuf);
    return 1;
}

int dk2::CEngineCompressedSurface::copySurf(CEngineSurfaceBase *dst, int dstx, int dsty) {
    if(patch::opengl_patch::enabled) {
        // convert to argb32 texture
        char tmpl_buf[sizeof(dk2::CEngineSurface)];
        dk2::CEngineSurface &tmpl = *(dk2::CEngineSurface *) tmpl_buf;
        *(void **) &tmpl = dk2::CEngineSurface::vftable;
        tmpl.width = this->width;
        tmpl.height = this->height;
        tmpl.pitch = this->width * dk2::MyCEngineSurfDesc_bgra32_instance.bytesPerPixel;
        tmpl.pixels = dk2::MyHeap_alloc(tmpl.height * tmpl.pitch);

        tmpl.fC_desc = &dk2::MyCEngineSurfDesc_bgra32_instance;
        tqia_init(tmpl.fC_desc->_rmask, tmpl.fC_desc->_gmask, tmpl.fC_desc->_bmask, tmpl.fC_desc->_amask);
        tqia_decompressJpeg(
                (uint8_t *) this->pixelBuf,
                (uint16_t *) tmpl.pixels, tmpl.pitch, tmpl.width, tmpl.height
        );
        // then just copy
        auto copyResult = patch::opengl_patch::copyBgra32ToTex(
                (uint8_t *) tmpl.pixels, tmpl.width, tmpl.height, tmpl.pitch, *dst, dstx, dsty
        ) ? 1 : 0;
//        auto copyResult = tmpl.v_copySurf(dst, dstx, dsty);
        dk2::MyHeap_free(tmpl.pixels);
        return copyResult;
    }
    if (!dst->v_hasBuf()) return 0;
    char *data = (char *) dst->v_lockBuf();
    tqia_init(dst->fC_desc->_rmask, dst->fC_desc->_gmask, dst->fC_desc->_bmask, dst->fC_desc->_amask);
    tqia_decompressJpeg(
            (uint8_t *) this->pixelBuf,
            (uint16_t *) (data + dst->pitch * dsty + dstx * dst->fC_desc->bytesPerPixel),
            dst->pitch, this->width, this->height
    );
    dst->v_unlockBuf(data);
    return 1;
}
