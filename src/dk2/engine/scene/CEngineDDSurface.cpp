//
// Created by DiaLight on 1/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/CEngineDDSurface.h"
#include "patches/opengl/opengl_patch.h"

namespace {
    int calcBitcount(unsigned int mask) {
        int bitcount = 0;
        for (unsigned int i = 0; i <= 31; ++i) {
            if ((1 << i) > mask)
                break;
            if ((mask & (1 << i)) != 0)
                ++bitcount;
        }
        return bitcount;
    }
}

void dk2::MyCEngineSurfDesc::initFromPixelFormat(LPDDPIXELFORMAT lpDDPixFmt) {
    this->bool0 = 1;
    this->ddPixFmt = *lpDDPixFmt;
    this->_rmask = lpDDPixFmt->dwRBitMask;
    this->_gmask = lpDDPixFmt->dwGBitMask;
    this->_bmask = lpDDPixFmt->dwBBitMask;
    this->_amask = lpDDPixFmt->dwRGBAlphaBitMask;
    this->_bitsiz = lpDDPixFmt->dwRGBBitCount;
    this->desc.dwRBitMask = lpDDPixFmt->dwRBitMask;
    this->desc.dwGBitMask = lpDDPixFmt->dwGBitMask;
    this->desc.dwBBitMask = lpDDPixFmt->dwBBitMask;
    this->desc.dwRGBAlphaBitMask = lpDDPixFmt->dwRGBAlphaBitMask;
    this->desc.dwRGBBitCount = lpDDPixFmt->dwRGBBitCount;
    this->desc.isBytePerPixel = 0;
    this->bytesPerPixel = lpDDPixFmt->dwRGBBitCount / 8;
    this->rbitcount = calcBitcount(lpDDPixFmt->dwRBitMask);
    this->gbitcount = calcBitcount(lpDDPixFmt->dwGBitMask);
    this->bbitcount = calcBitcount(lpDDPixFmt->dwBBitMask);
    this->abitcount = calcBitcount(lpDDPixFmt->dwRGBAlphaBitMask);
    this->bool2C = (lpDDPixFmt->dwFlags & 0x80000) != 0;
}

dk2::CEngineDDSurface *dk2::CEngineDDSurface::constructor(uint32_t width, uint32_t height, MyCEngineSurfDesc *desc, int useVideoMemory) {
    this->fC_desc = desc;
    *(void **) this = CEngineSurfaceBase::vftable;
    this->width = width;
    this->height = height;
    this->pitch = width * desc->bytesPerPixel;
    int try_level = 0;
    this->useVideoMemory = useVideoMemory;
    *(void **) this = CEngineDDSurface::vftable;
    DWORD flags;
    DWORD caps;
    if ((useVideoMemory & 1) != 0) {
        caps = 0x405008;
        static_assert((DDSCAPS_MIPMAP | DDSCAPS_VIDEOMEMORY | DDSCAPS_TEXTURE | DDSCAPS_COMPLEX) == 0x405008);
        flags = 0x21007;
        static_assert((DDSD_MIPMAPCOUNT | DDSD_PIXELFORMAT | DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS) == 0x21007);
    } else {
        caps = 0x1800;
        static_assert((DDSCAPS_SYSTEMMEMORY | DDSCAPS_TEXTURE) == 0x1800);
        flags = 0x1007;
        static_assert((DDSD_PIXELFORMAT | DDSD_WIDTH | DDSD_HEIGHT | DDSD_CAPS) == 0x1007);
    }

    DDSURFACEDESC2 surfDesc;
    memset(&surfDesc, 0, sizeof(surfDesc));
    surfDesc.dwWidth = width;
    surfDesc.ddsCaps.dwCaps = caps;
    surfDesc.dwSize = sizeof(DDSURFACEDESC2);
    static_assert(sizeof(DDSURFACEDESC2) == 0x7C);
    surfDesc.dwHeight = height;
    surfDesc.dwFlags = flags;
    surfDesc.ddpfPixelFormat = desc->ddPixFmt;
    surfDesc.dwMipMapCount = 1;

    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::createOglTexture(*this, surfDesc, (useVideoMemory & 1) != 0);
    } else {
        HRESULT hr = MyDirectDraw_instance_devTexture.dd4->CreateSurface(&surfDesc, &this->ddSurf, NULL);
        if (hr == DD_OK) {
            if ((useVideoMemory & 1) != 0)
                this->ddSurf->QueryInterface(CLSID_IDirect3DTexture2, (LPVOID *) &this->devTex);
            this->createError = 0;
        } else {
            this->ddSurf = NULL;
            this->createError = 1;
        }
    }
    return this;
}

void dk2::CEngineDDSurface::destructor() {
    *(void **) this = CEngineDDSurface::vftable;
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::destroy(*this);
    } else {
        if (!this->createError) {
            if ((this->useVideoMemory & 1) != 0)
                this->devTex->Release();
            this->ddSurf->Release();
        }
    }
    *(void **) this = CEngineSurfaceBase::vftable;
}


LPVOID dk2::CEngineDDSurface::lockBuf() {
    if(patch::opengl_patch::enabled) {
        return patch::opengl_patch::lock(*this);
    }
    DDSURFACEDESC2 desc;
    desc.dwSize = 124;
    RECT rect {0, 0, this->width, this->height};
    this->ddSurf->Lock(&rect, &desc, 1, NULL);
    this->pitch = desc.lPitch;
    return desc.lpSurface;
}
HRESULT dk2::CEngineDDSurface::unlockBuf(int a2) {
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::unlock(*this, (void *) a2);
        return DD_OK;
    }
    return this->ddSurf->Unlock(NULL);
}

int dk2::CEngineDDSurface::paintSurf(CEngineDDSurface *a2_src, int a3, int a4) {
    if (a2_src->v_f10_getKind() != 1) return 0;
    if (a3 != 0 || a4 != 0) return 0;
    if (this->width != a2_src->width || this->height != a2_src->height) return 0;
    if(this->fC_desc != a2_src->fC_desc) return 0;  // probably error

    if(patch::opengl_patch::enabled) {
        if(!patch::opengl_patch::copyTex(*this, *a2_src)) return 0;
        return 1;
    }
    if (this->ddSurf->BltFast(0, 0, a2_src->ddSurf, NULL, 16) == DDERR_SURFACELOST) {
        g_sc_isCurDdSurfLost = 1;
    }
    static_assert(DDERR_SURFACELOST == 0x887601C2);
    return 1;
}
