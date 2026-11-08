//
// Created by DiaLight on 5/6/2026.
//

#include "dk2/MyDdSurface.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"

#define SLOBYTE(x)   ((signed char)((x) & 0xFF))

LPDIRECTDRAWSURFACE __cdecl dk2::MyDdSurface_addRef(MyDdSurface *a1, int a2) {
    if(patch::opengl_patch::enabled) {
        return patch::opengl_patch::addRef(*a1, a2);
    }
    if (a2) {
        if (auto *surf = a1->dd_surface) surf->AddRef();
    }
    return a1->dd_surface;
}

int *__cdecl dk2::MyDdSurface_release(int *pstatus, MyDdSurface *a2) {
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::releaseOglTexture(*a2);
    } else {
        a2->dd_surface->Release();
        a2->dd_surface = NULL;
    }
    return *pstatus = 0, pstatus;
}

int *__cdecl dk2::MyDdSurfaceEx_lock(int *pstatus, MyDdSurfaceEx *surf, LPVOID *pLpsurface) {
    DDSURFACEDESC surfDesc;
    static_assert(sizeof(DDSURFACEDESC) == 108);
    surfDesc.dwSize = sizeof(DDSURFACEDESC);

    DWORD dwFlags = DDLOCK_WAIT;
    if (g_noSysLock)
        dwFlags |= DDLOCK_NOSYSLOCK;

    LPVOID lpSurface;
    if(patch::opengl_patch::enabled) {
        lpSurface = patch::opengl_patch::lock(*surf);
        patch::opengl_patch::getDesc(*surf, surfDesc);
    } else {
        if (HRESULT hResult = surf->dd_surf.dd_surface->Lock(NULL, &surfDesc, dwFlags, NULL)) {
            if (hResult == 0x887601C2 && MyDdSurfaceEx_restoreSurf_if_unk(surf))
                hResult = surf->dd_surf.dd_surface->Lock(NULL, &surfDesc, dwFlags, NULL);
            int status = hResult;
            if (status < 0) return *pstatus = status, pstatus;
        }
        lpSurface = surfDesc.lpSurface;
    }
    surf->fillDesc(&surfDesc);
    if (pLpsurface)
        *pLpsurface = lpSurface;
    return *pstatus = 0, pstatus;
}

HRESULT __cdecl dk2::MyDdSurfaceEx_unlock(MyDdSurfaceEx *a1) {
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::unlock(*a1);
        return DD_OK;
    } else {
        return a1->dd_surf.dd_surface->Unlock(NULL);
    }
}

int *__cdecl dk2::static_MyDdSurfaceEx_Blt(
        int *pstatus,
        MyDdSurfaceEx *a2_dstSurf, RECT *a3_dstRect,
        MyDdSurfaceEx *a4_srcSurf, RECT *a5_srcRect,
        int a6_flags) {
    MySurface *updated = a4_srcSurf->updateDesc();
    MySurface *v7 = a2_dstSurf->updateDesc();
    LONG w = v7->size.w;
    LONG h = v7->size.h;

    RECT v18_dst {0, 0, w, h};
    RECT v17_src {0, 0, updated->size.w, updated->size.h};

    RECT stubSrc;
    memset(&stubSrc, 0, sizeof(stubSrc));
    if (!a5_srcRect) {
//        RECT_sub_5D0F80(&stubSrc, &v17_src);
        stubSrc = v17_src;
        a5_srcRect = &stubSrc;
    }

    RECT stubDst;
    if (!a3_dstRect) {
//        RECT_sub_5D0F80(&stubDst, &v18_dst);
        stubDst = v18_dst;
        a3_dstRect = &stubDst;
    }

    DDBLTFX v25_ddBltfx;
    memset(&v25_ddBltfx, 0, sizeof(v25_ddBltfx));
    static_assert(sizeof(DDBLTFX) == 100);
    v25_ddBltfx.dwSize = sizeof(DDBLTFX);

    int dwFlags = a6_flags ^ DDBLT_WAIT;
    if ((a6_flags & 0x800) != 0) {
        dwFlags |= DDBLT_DDFX;
        v25_ddBltfx.dwDDFX |= 8u;
    }
    if ((a6_flags & 0x8000) != 0) {
        int dwColorSpaceValue;
        if (updated->desc.dwRGBBitCount == 8) {
            dwColorSpaceValue = (unsigned __int8) a4_srcSurf->dd_surf.dwColorSpaceValue_00;
        } else {
            MyBitMask rMask; rMask.constructor(updated->desc.dwRBitMask, 23);
            MyBitMask gMask; gMask.constructor(updated->desc.dwGBitMask, 15);
            MyBitMask bMask; bMask.constructor(updated->desc.dwBBitMask, 7);
            MyBitMask aMask; aMask.constructor(updated->desc.dwRGBAlphaBitMask, 31);
            DWORD shiftValue = *(DWORD *) &a4_srcSurf->dd_surf.fld10_00;
            dwColorSpaceValue =
                    aMask.mask & (shiftValue >> SLOBYTE(aMask.rshift) << SLOBYTE(aMask.lshift)) |
                    bMask.mask & (shiftValue >> SLOBYTE(bMask.rshift) << SLOBYTE(bMask.lshift)) |
                    gMask.mask & (shiftValue >> SLOBYTE(gMask.rshift) << SLOBYTE(gMask.lshift)) |
                    rMask.mask & (shiftValue >> SLOBYTE(rMask.rshift) << SLOBYTE(rMask.lshift));
        }
        DDCOLORKEY colorKey;
        colorKey.dwColorSpaceLowValue = dwColorSpaceValue;
        colorKey.dwColorSpaceHighValue = dwColorSpaceValue;
        a4_srcSurf->dd_surf.dd_surface->SetColorKey(8, &colorKey);
        dwFlags |= DDBLT_KEYSRC;  // use color key
    }

    if(patch::opengl_patch::enabled) {
        if(!patch::opengl_patch::bltTexture(*a2_dstSurf, a3_dstRect, *a4_srcSurf, a5_srcRect)) {
            return *pstatus = -1, pstatus;
        }
    } else {
        HRESULT hResult = a2_dstSurf->dd_surf.dd_surface->Blt(
                a3_dstRect,
                a4_srcSurf->dd_surf.dd_surface, a5_srcRect,
                dwFlags, &v25_ddBltfx);
        if (hResult == DDERR_SURFACELOST) {
            static_assert(DDERR_SURFACELOST == 0x887601C2);
            MyDdSurfaceEx_restoreSurf_if_unk(a2_dstSurf);
            MyDdSurfaceEx_restoreSurf_if_unk(a4_srcSurf);
        }
        if (hResult) {
//        ret_void_0args_0(v13);
            return *pstatus = -1, pstatus;
        }
    }
    return *pstatus = 0, pstatus;
}

unsigned int dk2::MyBitMask::constructor(int bitmask, unsigned int a3) {
    this->mask = bitmask;
    unsigned int bit = 31;
    if (bitmask) {
        unsigned int v4 = 0x80000000;
        if (bitmask >= 0) {
            do {
                v4 >>= 1;
                --bit;
            } while ((v4 & bitmask) == 0);
        }
    }
    if (bit < a3) {
        this->lshift = 0;
        this->rshift = a3 - bit;
    } else {
        bit -= a3;
        this->rshift = 0;
        this->lshift = bit;
    }
    return bit;
}

int *__cdecl dk2::static_MyDdSurfaceEx_BltWait(
        int *pstatus,
        MyDdSurfaceEx *lpDstSurf, uint32_t dwX, uint32_t dwY,
        MyDdSurfaceEx *lpSrcSurf, AABB *pSrcRect,
        int dwTrans) {
    MySurface *updated = lpSrcSurf->updateDesc();
    lpDstSurf->updateDesc();

    RECT *lpSrcRect = (RECT *) pSrcRect;
    tagRECT srcRect;
    memset(&srcRect, 0, sizeof(srcRect));
    if (!pSrcRect) {
        srcRect.top = 0;
        srcRect.left = 0;
        srcRect.right = updated->size.w;
        srcRect.bottom = updated->size.h;
        lpSrcRect = &srcRect;
    }
    // #define DDBLTFAST_SRCCOLORKEY                   0x00000001
    if ((dwTrans & 1) != 0) {
        int dwColorSpaceValue;
        if (updated->desc.dwRGBBitCount == 8) {
            dwColorSpaceValue = (unsigned __int8) lpSrcSurf->dd_surf.dwColorSpaceValue_00;
        } else {
            MyBitMask rMask; rMask.constructor(updated->desc.dwRBitMask, 23);
            MyBitMask gMask; gMask.constructor(updated->desc.dwGBitMask, 15);
            MyBitMask bMask; bMask.constructor(updated->desc.dwBBitMask, 7);
            MyBitMask aMask; aMask.constructor(updated->desc.dwRGBAlphaBitMask, 31);
            DWORD shiftValue = *(DWORD *) &lpSrcSurf->dd_surf.fld10_00;
            dwColorSpaceValue =
                    aMask.mask & (shiftValue >> SLOBYTE(aMask.rshift) << SLOBYTE(aMask.lshift)) |
                    bMask.mask & (shiftValue >> SLOBYTE(bMask.rshift) << SLOBYTE(bMask.lshift)) |
                    gMask.mask & (shiftValue >> SLOBYTE(gMask.rshift) << SLOBYTE(gMask.lshift)) |
                    rMask.mask & (shiftValue >> SLOBYTE(rMask.rshift) << SLOBYTE(rMask.lshift));
        }
        DDCOLORKEY colorKey;
        colorKey.dwColorSpaceLowValue = dwColorSpaceValue;
        colorKey.dwColorSpaceHighValue = dwColorSpaceValue;

        // A color key is a specific color value that acts as "transparent" or "skip" during a blit operation
        if(!patch::opengl_patch::enabled) {
            lpSrcSurf->dd_surf.dd_surface->SetColorKey(DDCKEY_SRCBLT, &colorKey);
        } else {
            patch::opengl_patch::texSetSrcColorKey(*lpSrcSurf, dwColorSpaceValue);
        }
    }
    if(patch::opengl_patch::enabled) {
        RECT dstRect {
            (LONG) dwX, (LONG) dwY,
            (LONG) dwX + (lpSrcRect->right - lpSrcRect->left),
            (LONG) dwY + (lpSrcRect->bottom - lpSrcRect->top)};
        patch::opengl_patch::bltTexture(*lpDstSurf, &dstRect, *lpSrcSurf, lpSrcRect);
    } else {
        HRESULT hResult = lpDstSurf->dd_surf.dd_surface->BltFast(
                dwX, dwY,
                lpSrcSurf->dd_surf.dd_surface, lpSrcRect,
                dwTrans ^ DDBLTFAST_WAIT);
        static_assert(DDERR_SURFACELOST == 0x887601C2);
        if (hResult == DDERR_SURFACELOST) {
            MyDdSurfaceEx_restoreSurf_if_unk(lpDstSurf);
            MyDdSurfaceEx_restoreSurf_if_unk(lpSrcSurf);
        }
        if (hResult) {
            *pstatus = -1;
            return pstatus;
        }
    }
    return *pstatus = 0, pstatus;
}


int *__cdecl dk2::MyDdSurfaceEx_fillWithColor(
        int *pstatus, MyDdSurfaceEx *dstSurf,
        LPRECT dstRect, Bgraf a4_color, int a6_flags) {
    if(patch::opengl_patch::enabled) {
        if(!patch::opengl_patch::fillWithColor(*dstSurf, dstRect, a4_color)) return *pstatus = -1, pstatus;
        return *pstatus = 0, pstatus;
    }
    DDBLTFX blt;
    blt.dwSize = 100;
    MySurface *surf = dstSurf->updateDesc();
    switch ( surf->desc.dwRGBBitCount ) {
        case 8:
            blt.dwFillColor = a4_color.fill;
            break;
        case 16: {
            MyBitMask v14_r;
            MyBitMask v15_g;
            MyBitMask v16_b;
            MyBitMask v17_a;
            v14_r.constructor(surf->desc.dwRBitMask, 0x17u);
            v15_g.constructor(surf->desc.dwGBitMask, 0xFu);
            v16_b.constructor(surf->desc.dwBBitMask, 7u);
            v17_a.constructor(surf->desc.dwRGBAlphaBitMask, 0x1Fu);
            int v6 = (unsigned __int16)
                    (LOWORD(v17_a.mask) & (*(DWORD *)&a4_color.blue >> SLOBYTE(v17_a.rshift) << SLOBYTE(v17_a.lshift))
                    | LOWORD(v16_b.mask) & (*(DWORD *)&a4_color.blue >> SLOBYTE(v16_b.rshift) << SLOBYTE(v16_b.lshift))
                    | LOWORD(v15_g.mask) & (*(DWORD *)&a4_color.blue >> SLOBYTE(v15_g.rshift) << SLOBYTE(v15_g.lshift))
                    | LOWORD(v14_r.mask) & (*(DWORD *)&a4_color.blue >> SLOBYTE(v14_r.rshift) << SLOBYTE(v14_r.lshift)));
            blt.dwFillColor = v6 | (v6 << 16);
        } break;
        case 24: {
            MyBitMask v10_r;
            MyBitMask v11_g;
            MyBitMask v12_b;
            MyBitMask v13_a;
            v10_r.constructor(surf->desc.dwRBitMask, 0x17u);
            v11_g.constructor(surf->desc.dwGBitMask, 0xFu);
            v12_b.constructor(surf->desc.dwBBitMask, 7u);
            v13_a.constructor(surf->desc.dwRGBAlphaBitMask, 0x1Fu);
            blt.dwFillColor =
                    v13_a.mask & (*(DWORD *)&a4_color.blue >> SLOBYTE(v13_a.rshift) << SLOBYTE(v13_a.lshift))
                    | v12_b.mask & (*(DWORD *)&a4_color.blue >> SLOBYTE(v12_b.rshift) << SLOBYTE(v12_b.lshift))
                    | v11_g.mask & (*(DWORD *)&a4_color.blue >> SLOBYTE(v11_g.rshift) << SLOBYTE(v11_g.lshift))
                    | v10_r.mask & (*(DWORD *)&a4_color.blue >> SLOBYTE(v10_r.rshift) << SLOBYTE(v10_r.lshift));
        } break;
        case 32:
            blt.dwFillColor = a4_color.blue | ((a4_color.green | (*(unsigned __int16 *)&a4_color.red << 8)) << 8);
            break;
        default:
            break;
    }
    int v8_flags = a6_flags ^ 0x1000000;
    v8_flags |= DDBLT_COLORFILL;
    if (dstSurf->dd_surf.dd_surface->Blt(dstRect, 0, 0, v8_flags, &blt) != 0) return *pstatus = -1, pstatus;
    return *pstatus = 0, pstatus;
}
