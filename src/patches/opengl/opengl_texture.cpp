//
// Created by DiaLight on 6/18/2026.
//
#include "opengl_patch.h"
#include "dk2_globals.h"
#include "opengl_internal.h"
#include "dk2/engine/game_engine.h"
#include "dk2_functions.h"
#include "tools/png_support.h"
#include "tools/visual_debug.h"
#include "patches/logging.h"
#include <exception>
#include <iostream>


void patch::opengl_patch::createOglTexture(dk2::MyDdSurfaceEx &out_surf, size_t width, size_t height, bool videoMemory) {
    if(out_surf.dd_surf.dd_surface) {
        // recreate
        if(auto *tex = OglPatchTexture::get(out_surf.dd_surf)) {
            if(width != tex->width || height != tex->height) {
                tex->width = width;
                tex->height = height;
                tex_free(tex->data);
                tex->data = tex_malloc(width * height * 4);
                memset(tex->data, 0, width * height * 4);
                out_surf.surf.lPitch = width * 4;
                out_surf.surf.size = {(int) width, (int) height};
                tex->isChanged = true;
            }
            if(videoMemory) {
                if(!tex->textureId) {
                    glGenTextures(1, &tex->textureId);
                    tex->isChanged = true;
                }
            } else if(tex->textureId) {
                glDeleteTextures(1, &tex->textureId);
                tex->textureId = 0;
            }
            return;
        }
    }
    auto *tex = new OglPatchTexture {
            .width=width,
            .height=height,
            .bpp=32,
            .data=tex_malloc(width * height * 4),
    };
    memset(tex->data, 0, width * height * 4);
    if(videoMemory) {
        glGenTextures(1, &tex->textureId);
    }
    out_surf.dd_surf.dd_surface = (LPDIRECTDRAWSURFACE) tex;
    out_surf.surf.lpSurface = (LPVOID) 0x404;
    out_surf.surf.lPitch = width * 4;
    out_surf.surf.size = {(int) width, (int) height};
    out_surf.surf.desc.isBytePerPixel = false;
    out_surf.surf.desc.dwRGBBitCount = 32;
    out_surf.surf.desc.dwRBitMask = 0xFF0000;
    out_surf.surf.desc.dwGBitMask = 0xFF00;
    out_surf.surf.desc.dwBBitMask = 0xFF;
    out_surf.surf.desc.dwRGBAlphaBitMask = 0xFF000000;
}
void patch::opengl_patch::createOglTexture(dk2::MyDdSurfaceEx &out_surf, dk2::MySurface &in_surf, bool videoMemory) {
    if(in_surf.lpSurface) dump(in_surf, "in_surf");
    createOglTexture(out_surf, in_surf.size.w, in_surf.size.h, videoMemory);
}

LPDIRECTDRAWSURFACE patch::opengl_patch::addRef(LPDIRECTDRAWSURFACE &surf, bool _addRef) {
    if(auto *tex = OglPatchTexture::get(surf)) {
        if(_addRef) tex->refs++;
    }
    return surf;
}
void patch::opengl_patch::releaseOglTexture(LPDIRECTDRAWSURFACE &surf) {
    if(auto *tex = OglPatchTexture::get(surf)) tex->release();
    surf = NULL;
}
LPVOID patch::opengl_patch::lock(dk2::MyDdSurface &surf) {
    if(auto *tex = OglPatchTexture::get(surf)) return tex->data;
    return NULL;
}
void patch::opengl_patch::unlock(dk2::MyDdSurfaceEx &surf) {
    if(auto *tex = OglPatchTexture::get(surf.dd_surf)) {
        tex->isChanged = true;
    }
}

void patch::opengl_patch::createOglTexture(dk2::CEngineDDSurface &out_surf, DDSURFACEDESC2 &in_desc, bool videoMemory) {
    if(out_surf.ddSurf) {
        throw std::exception("unimplemented");
    }
    if(in_desc.ddpfPixelFormat.dwRGBBitCount == 32) {
        auto *tex = new OglPatchTexture {
                .width=in_desc.dwWidth,
                .height=in_desc.dwHeight,
                .bpp=32,
                .data=tex_malloc(in_desc.dwWidth * in_desc.dwHeight * 4),
        };
        memset(tex->data, 0, in_desc.dwWidth * in_desc.dwHeight * 4);
        if(videoMemory) {
            glGenTextures(1, &tex->textureId);
            out_surf.useVideoMemory = 1;
        } else {
            out_surf.useVideoMemory = 0;
        }
        out_surf.ddSurf = (LPDIRECTDRAWSURFACE4) tex;
        out_surf.pitch = in_desc.dwWidth * 4;
        out_surf.width = in_desc.dwWidth;
        out_surf.height = in_desc.dwHeight;
    } else if(in_desc.ddpfPixelFormat.dwRGBBitCount == 16) {
        auto *tex = new OglPatchTexture {
                .width=in_desc.dwWidth,
                .height=in_desc.dwHeight,
                .bpp=16,
                .data=tex_malloc(in_desc.dwWidth * in_desc.dwHeight * 2),
        };
        memset(tex->data, 0, in_desc.dwWidth * in_desc.dwHeight * 2);
        if(videoMemory) {
            glGenTextures(1, &tex->textureId);
            out_surf.useVideoMemory = 1;
        } else {
            out_surf.useVideoMemory = 0;
        }
        out_surf.ddSurf = (LPDIRECTDRAWSURFACE4) tex;
        out_surf.pitch = in_desc.dwWidth * 2;
        out_surf.width = in_desc.dwWidth;
        out_surf.height = in_desc.dwHeight;
    } else {
        throw std::exception("unsupported");
    }
}

LPVOID patch::opengl_patch::lock(dk2::CEngineDDSurface &surf) {
    if(auto *tex = OglPatchTexture::get(surf)) return tex->data;
    return NULL;
}
void patch::opengl_patch::unlock(dk2::CEngineDDSurface &surf, LPVOID buf) {
    if(auto *tex = OglPatchTexture::get(surf)) {
        tex->isChanged = true;
    }
}
void patch::opengl_patch::destroy(dk2::CEngineDDSurface &surf) {
    if(auto *tex = OglPatchTexture::get(surf)) tex->release();
    surf.ddSurf = NULL;
}

bool patch::opengl_patch::getDesc(dk2::MyDdSurfaceEx &surf, DDSURFACEDESC &desc) {
    ZeroMemory(&desc, sizeof(desc));
    if(auto *tex = OglPatchTexture::get(surf.dd_surf)) {
        if(tex->bpp == 32) {
            desc.dwWidth = tex->width;
            desc.dwHeight = tex->height;
            desc.lpSurface = tex->data;
            desc.lPitch = tex->width * 4;
            desc.ddpfPixelFormat.dwRGBBitCount = 32;
            desc.ddpfPixelFormat.dwRBitMask = 0xFF0000;
            desc.ddpfPixelFormat.dwGBitMask = 0xFF00;
            desc.ddpfPixelFormat.dwBBitMask = 0xFF;
            desc.ddpfPixelFormat.dwRGBAlphaBitMask = 0xFF000000;
        } else {
            throw std::exception("unimplemented");
        }
        return true;
    }
    throw std::exception("unexpected");
    return false;
}
void patch::opengl_patch::texSetSrcColorKey(dk2::MyDdSurfaceEx &dst, DWORD color) {
    if(auto *tex = OglPatchTexture::get(dst.dd_surf)) {
        tex->srcColorKey = color;
    }
}
void bltTexture(OglPatchTexture &dst, const RECT &dstRect, OglPatchTexture &src, const RECT &srcRect) {
    SIZE sz {
            std::min(srcRect.right - srcRect.left, dstRect.right - dstRect.left),
            std::min(srcRect.bottom - srcRect.top, dstRect.bottom - dstRect.top)
    };

    if(dstRect.left >= dst.width || dstRect.right < 0 || dstRect.top >= dst.height || dstRect.bottom < 0) {
//        throw std::exception("unexpected");
        return;
    }
    if(srcRect.left >= src.width || srcRect.right < 0 || srcRect.top >= src.height || srcRect.bottom < 0) {
//        throw std::exception("unexpected");
        return;
    }

    // dst clipping
    if(dstRect.right > dst.width) sz.cx = std::min(sz.cx, (LONG) dst.width - dstRect.left);
    if(dstRect.bottom > dst.height) sz.cy = std::min(sz.cy, (LONG) dst.height - dstRect.top);

    // src clipping
    if(srcRect.right > src.width) sz.cx = std::min(sz.cx, (LONG) src.width - srcRect.left);
    if(srcRect.bottom > src.height) sz.cy = std::min(sz.cy, (LONG) src.height - srcRect.top);

    if(sz.cx <= 0 || sz.cy <= 0) {
//        throw std::exception("unexpected");
        return;
    }

    if(src.bpp != dst.bpp) throw std::exception("unimplemented");

    if(dst.bpp == 32) {
        size_t src_pitch = src.width * 4;
        size_t dst_pitch = dst.width * 4;
        auto *sline = (uint8_t *) src.data + (srcRect.top * src_pitch);
        auto *dline = (uint8_t *) dst.data + (dstRect.top * dst_pitch);
        for (int dy = 0; dy < sz.cy; ++dy) {
            auto *spos = (uint32_t *) (sline + srcRect.left * 4);
            auto *dpos = (uint32_t *) (dline + dstRect.left * 4);
            for (int dx = 0; dx < sz.cx; ++dx) {
                uint32_t pix = spos[dx];
                if(src.srcColorKey && pix == src.srcColorKey) continue;
                dpos[dx] = pix;
            }
            sline += src_pitch;
            dline += dst_pitch;
        }
    } else if(dst.bpp == 16) {
        size_t src_pitch = src.width * 2;
        size_t dst_pitch = dst.width * 2;
        auto *sline = (uint8_t *) src.data + (srcRect.top * src_pitch);
        auto *dline = (uint8_t *) dst.data + (dstRect.top * dst_pitch);
        for (int dy = 0; dy < sz.cy; ++dy) {
            auto *spos = (uint16_t *) (sline + srcRect.left * 2);
            auto *dpos = (uint16_t *) (dline + dstRect.left * 2);
            for (int dx = 0; dx < sz.cx; ++dx) {
                uint16_t pix = spos[dx];
                if(src.srcColorKey && pix == src.srcColorKey) continue;
                dpos[dx] = pix;
            }
            sline += src_pitch;
            dline += dst_pitch;
        }
    } else {
        throw std::exception("unimplemented");
    }
    dst.isChanged = true;
}
bool patch::opengl_patch::fillWithColor(LPDIRECTDRAWSURFACE surf, LPRECT pRect, dk2::Bgraf color) {
    if(auto *tex = OglPatchTexture::get(surf)) {
        if(tex->bpp != 32) throw std::exception("unimplemented");
        RECT rect {0, 0, (LONG) tex->width, (LONG) tex->height};
        if(pRect) rect = *pRect;

        SIZE sz { rect.right - rect.left, rect.bottom - rect.top };

        sz.cx = std::min(sz.cx, (LONG) tex->width - rect.left);
        sz.cy = std::min(sz.cy, (LONG) tex->height - rect.top);

        size_t pitch = tex->width * 4;
        auto *line = (uint8_t *) tex->data;
        for (int dy = 0; dy < sz.cy; ++dy) {
            auto *pos = (uint32_t *) (line + rect.left * 4);
            for (int dx = 0; dx < sz.cx; ++dx) {
                auto *pix = (uint8_t *) &pos[dx];
                pix[0] = color.blue;
                pix[1] = color.green;
                pix[2] = color.red;
                pix[3] = color.alpha;
            }
            line += pitch;
        }
        tex->isChanged = true;
        return true;
    }
//    glClearColor(color.red / 256.f, color.green / 256.f, color.blue / 256.f, color.alpha / 256.f);
//    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    return false;
}

bool patch::opengl_patch::bltTexture(dk2::MyDdSurfaceEx &dst, RECT *pDstRect, dk2::MyDdSurfaceEx &src, RECT *pSrcRect) {
    if(auto *srcTex = OglPatchTexture::get(src.dd_surf)) {
//        dump_rgba32(srcTex->data, srcTex->width, srcTex->height, srcTex->width * 4, "srcTex");
        if(auto *dstTex = OglPatchTexture::get(dst.dd_surf)) {
            if(patch::opengl_patch::noSoftwareScale) {
                // catch software scale attempt
                if(pDstRect == NULL) {
                    dk2::Size2i srcSize {
                            (int) (pSrcRect ? pSrcRect->right - pSrcRect->left : srcTex->width),
                            (int) (pSrcRect ? pSrcRect->bottom - pSrcRect->top : srcTex->height)
                    };
                    if(dstTex->width != srcSize.w || dstTex->height != srcSize.h) {
                        dump(src, "src", 1);
                        dump(dst, "dst", 1);
                        printf("");
                    }
                }
            }
            RECT dstRect {0, 0, (LONG) dstTex->width, (LONG) dstTex->height};
            RECT srcRect {0, 0, (LONG) srcTex->width, (LONG) srcTex->height};
            if(!pDstRect) pDstRect = &dstRect;
            if(!pSrcRect) pSrcRect = &srcRect;
            bltTexture(*dstTex, *pDstRect, *srcTex, *pSrcRect);
            return true;
        } else {
            throw std::exception("unexpected");
            return false;
        }
    } else {
        throw std::exception("unexpected");
        return false;
    }
}
bool patch::opengl_patch::copyTex(dk2::CEngineDDSurface &dst, dk2::CEngineDDSurface &src) {
    if(auto *srcTex = OglPatchTexture::get(src)) {
//        dump_rgba32(srcTex->data, srcTex->width, srcTex->height, srcTex->width * 4, "srcTex");
        if(auto *dstTex = OglPatchTexture::get(dst)) {
            RECT dstRect {0, 0, (LONG) dstTex->width, (LONG) dstTex->height};
            RECT srcRect {0, 0, (LONG) srcTex->width, (LONG) srcTex->height};
            bltTexture(*dstTex, dstRect, *srcTex, srcRect);
            return true;
        } else {
            throw std::exception("unexpected");
            return false;
        }
    } else {
        throw std::exception("unexpected");
        return false;
    }
}
bool patch::opengl_patch::copyBgra32ToTex(
        uint8_t *data, size_t width, size_t height, size_t pitch,
        dk2::CEngineSurfaceBase &dst, size_t dstX, size_t dstY) {
    OglPatchTexture *dstTex;
    if(dst.getVtbl() == dk2::CEngineSurface::vftable) {
        auto &dstSurf = *(dk2::CEngineSurface *) &dst;
        size_t dst_pitch = dstSurf.width * 4;
        auto *sline = (uint8_t *) data;
        auto *dline = (uint8_t *) dstSurf.pixels + dstY * dst_pitch;
        for (int dy = 0; dy < height; ++dy) {
            auto *spos = (uint32_t *) (sline);
            auto *dpos = (uint32_t *) (dline + dstX * 4);
            for (int dx = 0; dx < width; ++dx) {
                dpos[dx] = spos[dx];
            }
            sline += pitch;
            dline += dst_pitch;
        }
        return true;
    } else if(dst.getVtbl() == dk2::CEngineDDSurface::vftable) {
        dstTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) &dst);
    } else {
        throw std::exception("unimplemented surfaace type");
    }
    if(dstTex) {
//        dump_bgra32(data, width, height, pitch, "img");

        size_t dst_pitch = dstTex->width * 4;
        auto *sline = (uint8_t *) data;
        auto *dline = (uint8_t *) dstTex->data + dstY * dst_pitch;
        for (int dy = 0; dy < height; ++dy) {
            auto *spos = (uint32_t *) (sline);
            auto *dpos = (uint32_t *) (dline + dstX * 4);
            for (int dx = 0; dx < width; ++dx) {
                dpos[dx] = spos[dx];
            }
            sline += pitch;
            dline += dst_pitch;
        }
        dstTex->isChanged = true;
        return true;
    }
    throw std::exception("unexpected");
    return false;
}

bool patch::opengl_patch::bindTex(size_t stage, LPDIRECTDRAWSURFACE surf) {
    if(auto *tex = OglPatchTexture::get(surf)) {
        tex->copyToVideoMemory();
        if (GLuint textureId = tex->textureId) {
//            // Select the texture unit (equivalent to SetTexture stage)
//            glActiveTexture(GL_TEXTURE0_ARB + stage);
            // Bind the texture (equivalent to passing pTexture)

            g_oglCtx.glActiveTexture(GL_TEXTURE0 + stage);
            glBindTexture(GL_TEXTURE_2D, textureId);
            return true;
        }
    }
    throw std::exception("unexpected");
    return false;
}
void patch::opengl_patch::dumpTex(LPDIRECTDRAWSURFACE surf, const char *title, int scale, int timeout) {
    if(auto *tex = OglPatchTexture::get(surf)) {
        dump_bgra32(tex->data, tex->width, tex->height, tex->width * 4, title, scale, timeout);
    }
}

