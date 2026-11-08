//
// Created by DiaLight on 3/30/2025.
//
#include <dk2_globals.h>
#include <dk2_functions.h>
#include <dk2/dk2_memory.h>
#include <dk2/MySurface.h>
#include <patches/logging.h>
#include <patches/micro_patches.h>
#include "patches/opengl/opengl_patch.h"


dk2::MySurface *__cdecl dk2::static_CBridge_loadPng(const char *name) {
    char Buffer[1024];
    if (!MyResources_instance.gameCfg.EnableArtPatching) {
        sprintf(Buffer, "Attempt To Load PNG without artpatch : %s", name);
        patch::log::dbg("%s", Buffer);
    }
    MySurface *surf = g_pCBridge->v_loadPng(name);
    if (patch::null_surf_fix::enabled) {
        if (surf == NULL) {
            surf = &patch::null_surf_fix::emptySurf;
            patch::log::dbg("[fix] tried to load \"%s\" PNG but NULL returned. replace with empty texture", name);
        }
    }
    return surf;
}

int *dk2::MySurface_static_copy(int *pstatus, MySurface *dst, int x, int y, MySurface *src, AABB *aabb, int a7) {
    if (!src->size.h) return *pstatus = -1, pstatus;
    if (!src->size.w) return *pstatus = -1, pstatus;
    if (src->desc.dwRBitMask != g_confSurfDesc_bgra32.dwRBitMask) return *pstatus = -1, pstatus;
    if (src->desc.dwGBitMask != g_confSurfDesc_bgra32.dwGBitMask) return *pstatus = -1, pstatus;
    if (src->desc.dwBBitMask != g_confSurfDesc_bgra32.dwBBitMask) return *pstatus = -1, pstatus;
    if (src->desc.dwRGBAlphaBitMask != g_confSurfDesc_bgra32.dwRGBAlphaBitMask) return *pstatus = -1, pstatus;
    if (src->desc.dwRGBBitCount != g_confSurfDesc_bgra32.dwRGBBitCount) return *pstatus = -1, pstatus;
    if ((src->desc.isBytePerPixel == 0) != (g_confSurfDesc_bgra32.isBytePerPixel == 0)) return *pstatus = -1, pstatus;
    if (!src->lpSurface) return *pstatus = -1, pstatus;
    if (!dst->lpSurface) return *pstatus = -1, pstatus;

    Size2i v12 {dst->size.w, dst->size.h};
    Pos2i v13 {0, 0};
    AABB tmp;
    tmp.constructor2(&v13, &v12);

    Size2i v14 {src->size.w, src->size.h};
    Pos2i v15 {0, 0};
    AABB v16;
    v16.constructor2(&v15, &v14);

    if (aabb) {
        if (aabb->minX > aabb->maxX || aabb->minY > aabb->maxY || !v16.contains(aabb)) return *pstatus = -1, pstatus;
    }
    int v9 = a7;
    if (MyResources_instance.video_settings.stipple_alpha && !a7)
        v9 = 2;
    if (dst->desc.dwRBitMask == 0xF800
        && dst->desc.dwGBitMask == 0x7E0
        && dst->desc.dwBBitMask == 0x1F
        && !dst->desc.dwRGBAlphaBitMask
        && dst->desc.dwRGBBitCount == 16
        && !dst->desc.isBytePerPixel) {
        probably_copySurface_16bpp_noAlpha(pstatus, dst, x, y, src, aabb, v9);
        return pstatus;
    }
    MySurfDesc tex;
    if (dst->desc.dwRBitMask == 0x7C00
        && dst->desc.dwGBitMask == 0x3E0
        && dst->desc.dwBBitMask == 0x1F
        && !dst->desc.dwRGBAlphaBitMask
        && dst->desc.dwRGBBitCount == 16
        && !dst->desc.isBytePerPixel
        || (tex.constructor(0x7C00, 0x3E0, 0x1F, 0x8000, 16, 0), dst->desc.dwRBitMask == tex.dwRBitMask)
           && dst->desc.dwGBitMask == tex.dwGBitMask
           && dst->desc.dwBBitMask == tex.dwBBitMask
           && dst->desc.dwRGBAlphaBitMask == tex.dwRGBAlphaBitMask
           && dst->desc.dwRGBBitCount == tex.dwRGBBitCount
           && (dst->desc.isBytePerPixel == 0) == (tex.isBytePerPixel == 0)) {
        probably_copySurface_16bpp_alphaMask(pstatus, dst, x, y, src, aabb, v9);
        return pstatus;
    }
    tex.constructor(0xFF0000, 0xFF00, 0xFF, 0, 32, 0);
    if (dst->desc.dwRBitMask == tex.dwRBitMask
        && dst->desc.dwGBitMask == tex.dwGBitMask
        && dst->desc.dwBBitMask == tex.dwBBitMask
        && dst->desc.dwRGBAlphaBitMask == tex.dwRGBAlphaBitMask
        && dst->desc.dwRGBBitCount == tex.dwRGBBitCount
        && (dst->desc.isBytePerPixel == 0) == (tex.isBytePerPixel == 0)) {
        probably_copySurface_32bpp(pstatus, dst, x, y, src, aabb, v9);
        return pstatus;
    }
    if (patch::opengl_patch::enabled) {
        tex.constructor(0xFF0000, 0xFF00, 0xFF, 0xFF000000, 32, 0);
        if (dst->desc.dwRBitMask == tex.dwRBitMask
            && dst->desc.dwGBitMask == tex.dwGBitMask
            && dst->desc.dwBBitMask == tex.dwBBitMask
            && dst->desc.dwRGBAlphaBitMask == tex.dwRGBAlphaBitMask
            && dst->desc.dwRGBBitCount == tex.dwRGBBitCount
            && (dst->desc.isBytePerPixel == 0) == (tex.isBytePerPixel == 0)) {
            probably_copySurface_32bpp(pstatus, dst, x, y, src, aabb, v9);
            return pstatus;
        }
    }
    tex.constructor(0xF00, 0xF0, 0xF, 0xF000, 16, 0);
    if (dst->desc.dwRBitMask == tex.dwRBitMask
        && dst->desc.dwGBitMask == tex.dwGBitMask
        && dst->desc.dwBBitMask == tex.dwBBitMask
        && dst->desc.dwRGBAlphaBitMask == tex.dwRGBAlphaBitMask
        && dst->desc.dwRGBBitCount == tex.dwRGBBitCount
        && (dst->desc.isBytePerPixel == 0) == (tex.isBytePerPixel == 0)) {
        probably_copySurface_16bpp(pstatus, dst, x, y, src, aabb, v9);
        return pstatus;
    }
    if (((dst->desc.dwRGBBitCount + 7) & ~7) == 16 && !dst->desc.isBytePerPixel) {
        probably_copySurface_8bpp(pstatus, dst, x, y, src, aabb, v9);
        return pstatus;
    }
    return *pstatus = -1, pstatus;
}

int *dk2::probably_copySurface_32bpp(
        int *pstatus,
        MySurface *dst,
        int dst_x, int dst_y,
        MySurface *src,
        AABB *src_area, int alphaBlend) {
    char *lineSrc = (char *) src->lpSurface;
    int width = src->size.w;
    int height = src->size.h;
    if (src_area) {
        lineSrc += 4 * src_area->minX + src_area->minY * src->lPitch;
        height = src_area->maxY - src_area->minY;
        width = src_area->maxX - src_area->minX;
        if(patch::opengl_patch::enabled) {
            if(src_area->maxX > src->size.w) throw std::exception("src area overlap");
            if(src_area->maxY > src->size.h) throw std::exception("src area overlap");
        }
    }
    if(patch::opengl_patch::enabled) {
        if(dst_x + width > dst->size.w) throw std::exception("dst area overlap");
        if(dst_y + height > dst->size.h) throw std::exception("dst area overlap");
    }
    char *lineDst = (char *) dst->lpSurface + 4 * dst_x + dst->lPitch * dst_y;
    if (alphaBlend != 1) {
        for (int y = 0; y < height; ++y) {
            int *posSrc = (int *) lineSrc;
            int *posDst = (int *) lineDst;
            for (int x = 0; x < width; ++x) {
                uint32_t pixSrc = *posSrc;
                uint32_t pixDst = *posDst;

                uint32_t src_A = pixSrc >> 24;
                if (src_A == 0xFF) {
                    *posDst = pixSrc | pixDst & 0xFF000000;
                } else if (src_A) {
#define BYTE0(d) ((int32_t) ((((uint32_t)(d)) >> 0) & 0xff))
#define BYTE1(d) ((int32_t) ((((uint32_t)(d)) >> 8) & 0xff))
#define BYTE2(d) ((int32_t) ((((uint32_t)(d)) >> 16) & 0xff))

                    int32_t src_R = BYTE0(pixSrc);
                    int32_t src_G = BYTE1(pixSrc);
                    int32_t src_B = BYTE2(pixSrc);

                    int32_t dst_R = BYTE0(pixDst);
                    int32_t dst_G = BYTE1(pixDst);
                    int32_t dst_B = BYTE2(pixDst);

                    // https://grokipedia.com/page/RGBA_color_model#software-handling
#define BLEND_WIKI(s, d, a) (((s) * (a) + (d) * (255 - (a))) / 255)
#define BLEND_OPT(s, d, a) (((d) << 8) + ((a) * ((s) - (d))) >> 8)  // same as wiki

                    uint32_t blue_shl0 = (BLEND_OPT(src_R, dst_R, src_A) << 0) & 0x000000FF;
                    uint32_t green_shl8 = (BLEND_OPT(src_G, dst_G, src_A) << 8) & 0x0000FF00;
                    uint32_t red_shl16 = (BLEND_OPT(src_B, dst_B, src_A) << 16) & 0x00FF0000;

                    uint32_t alpha_shl24 = pixDst & 0xFF000000;  // DK2 is just using dst alpha
//                    new_A = src_A + dst_A * (255 - src_A) / 255  // Straight (unassociated) alpha handling

//                    if(patch::opengl_patch::enabled) {
//                        // I am always using alpha textures. Don't preserve alpha on full alpha
//                        if(alpha_shl24 == 0) alpha_shl24 = pixSrc & 0xFF000000;
//                    }

                    *posDst = alpha_shl24 | red_shl16 | green_shl8 | blue_shl0;
                }


                ++posSrc;
                ++posDst;
            }
            lineSrc += src->lPitch;
            lineDst += dst->lPitch;
        }
        return *pstatus = 0, pstatus;
    }
    int v14_height = height;
    int v15_height = height - 1;
    if (!v14_height) return *pstatus = 0, pstatus;
    int y_ = v15_height + 1;
    do {
        DWORD *v16 = (DWORD *) lineDst;
        if (width) {
            int x_ = width;
            do {
                uint32_t v18_pix = *v16;
                *v16 = *(DWORD *) lineSrc | v18_pix & 0xFF000000;
                v16++;
                --x_;
            } while (x_);
        }
        lineSrc += src->lPitch;
        lineDst += dst->lPitch;
        --y_;
    } while (y_);
    return *pstatus = 0, pstatus;
}

