//
// Created by DiaLight on 6/1/2026.
//
#include <dk2/MyNBitTexture.h>
#include <dk2/text/render/MyStringTexture.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"


void __cdecl dk2::MyNBitTexture_initWithSurf(MySurface *a1_surf) {
    if (a1_surf) {
        g_MyNBitTexture_myRenderSurface = a1_surf;
        g_MyNBitTexture_lpSurface = a1_surf->lpSurface;
        MyNBitTexture_AABB_sub_5B3510(NULL);
        switch (g_MyNBitTexture_myRenderSurface->desc.dwRGBBitCount) {
            case 16:
                pMyNBitTexture = (MyNBitTexture *) &My16BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            case 24:
                pMyNBitTexture = (MyNBitTexture *) &My24BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            case 32:
                pMyNBitTexture = (MyNBitTexture *) &My32BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            default:
                pMyNBitTexture = (MyNBitTexture *) &My8BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
        }
    } else {
        g_MyNBitTexture_myRenderSurface = NULL;
    }
}

void __cdecl dk2::MyNBitTexture_initWithSurfEx(MyDdSurfaceEx *surf) {
    if (surf) {
        g_MyNBitTexture_myRenderSurface = surf->updateDesc();
        g_MyNBitTexture_lpSurface = g_MyNBitTexture_myRenderSurface->lpSurface;
        g_MyNBitTexture_surf_f0 = surf->dd_surf.f0;
        g_MyNBitTexture_surf_f4 = (BYTE *) surf->dd_surf.f4;
        g_MyNBitTexture_surf_f8 = surf->dd_surf.f8;
        g_MyNBitTexture_fill2PaletteMap = (BYTE *) surf->dd_surf.fill2PaletteMap;
        MyNBitTexture_AABB_sub_5B3510(NULL);
        switch (g_MyNBitTexture_myRenderSurface->desc.dwRGBBitCount) {
            case 16:
                pMyNBitTexture = (MyNBitTexture *) &My16BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            case 24:
                pMyNBitTexture = (MyNBitTexture *) &My24BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            case 32:
                pMyNBitTexture = (MyNBitTexture *) &My32BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
            default:
                pMyNBitTexture = (MyNBitTexture *) &My8BitTexture_instance;
                g_MyRgbaBitMask_instance.init(g_MyNBitTexture_myRenderSurface);
                break;
        }
    } else {
        g_MyNBitTexture_myRenderSurface = NULL;
    }
}

char dk2::CFrontEndComponent::drawText(MyStringTexture *mst) {
    int status;

    if ((g_lazyInitFlags & 1) == 0) {
        g_lazyInitFlags |= 1u;
        g_MyTextRenderer_instance_70D608.constructor();
        atexit(unknown_libname_17);
    }
    if ((g_lazyInitFlags & 2) == 0) {
        g_lazyInitFlags |= 2u;
        g_mySurface_0.constructor_empty();
        atexit(nullsub_17);
    }
    if ((g_lazyInitFlags & 4) == 0) {
        g_lazyInitFlags |= 4u;
        g_surf_a4.constructor_empty();
        atexit(nullsub_16);
    }
    switch (mst->fontObjType) {
        case 1: break;
        case 2: g_curFontObj = &g_FontObj2_instance; break;
        case 3: g_curFontObj = &g_FontObj3_instance; break;
        case 4: g_curFontObj = &g_FontObj4_instance; break;
        case 5: g_curFontObj = &g_FontObj5_instance; break;
        case 6: g_curFontObj = &g_FontObj6_instance; break;
        case 7: g_curFontObj = &g_FontObj7_instance; break;
        case 8: g_curFontObj = &g_FontObj8_instance; break;
        case 9: g_curFontObj = &g_FontObj9_instance; break;
        default:
            return 0;
    }

    g_curFontObj->reset_f10(&status);
    g_mySurface_p2 = g_MyNBitTexture_myRenderSurface;
    MyNBitTexture_initWithSurf(mst->surf_360C);
    switch (mst->fld21_2) {
        case 0:
            g_MyTextRenderer_instance_70D608.selectMyCR(&status, 0);
            g_MyTextRenderer_instance_70D608.selectMyTR(&status, 2);
            break;
        case 1:
            g_MyTextRenderer_instance_70D608.selectMyCR(&status, 1);
            g_MyTextRenderer_instance_70D608.selectMyTR(&status, 2);
            break;
        case 2:
            g_MyTextRenderer_instance_70D608.selectMyCR(&status, 2);
            g_MyTextRenderer_instance_70D608.selectMyTR(&status, 2);
            break;
        case 3:
            g_MyTextRenderer_instance_70D608.selectMyCR(&status, 3);
            g_MyTextRenderer_instance_70D608.selectMyTR(&status, 3);
            break;
        default:
            break;
    }
    g_curFontObj->setColor(&status, mst->pColor14);

    g_MyTextRenderer_instance_70D608.renderText(
            &status, mst->aabb,
            (uint8_t *) mst->string_MB,
            g_curFontObj, mst->cur_aabb);

    mst->cur_aabb->minX -= 6;
    mst->cur_aabb->maxX += 6;
    mst->cur_aabb->minY -= 6;
    mst->cur_aabb->maxY += 6;

    if (*mst->surf_360C->subSurface(&status, &g_mySurface_0, mst->cur_aabb) < 0) return 0;
    if (*mst->surf_39A4->subSurface(&status, &g_surf_a4, mst->cur_aabb) < 0) return 0;

    int f1C_fld1C_3 = mst->fld1C_3 ? (uint8_t) mst->fld1C_3 : 3;

    if(patch::opengl_patch::enabled) {
//        dump(*mst->surf_360C, "text1");  // text
//        dump(*mst->surf_39A4, "text1");  // empty
    }

    if (mst->pColor18) {
        this->cglow.sub_5524F0(&status, &g_surf_a4, &g_mySurface_0, f1C_fld1C_3, mst->pColor18);
    } else {
        this->cglow.sub_5524F0(
                &status,
                &g_surf_a4, &g_mySurface_0,
                f1C_fld1C_3, &this->color30332
        );
    }

    if(patch::opengl_patch::enabled) {
//        dump(*mst->surf_360C, "text2");  // text
//        dump(*mst->surf_39A4, "text2");  // blurred
    }

    this->cglow.sub_552620(&status, &g_mySurface_0, &g_surf_a4, 1.0);

    if(patch::opengl_patch::enabled) {
//        dump(*mst->surf_360C, "text3");  // blurred
//        dump(*mst->surf_39A4, "text3");  // blurred
    }

    g_curFontObj->checkFlag8(&status);
    g_MyTextRenderer_instance_70D608.renderText(
            &status, mst->aabb,
            (uint8_t *) mst->string_MB,
            g_curFontObj, NULL);


    if(patch::opengl_patch::enabled) {
//        dump(*mst->surf_360C, "text4");  // text + blur
//        dump(*mst->surf_39A4, "text4");  // blurred
    }

    g_curFontObj->setColor(&status, &this->color5FF4);
    MyNBitTexture_initWithSurf(g_mySurface_p2);
    return 1;
}


char dk2::MyNBitTexture::f4_5C4D40(AABB *aabb, Bgraf a3_color) {
    if ((g_MyNBitTexture_surf_f0 & 4) != 0) {
        return this->v_f8(aabb, a3_color);
    } else {
        return this->v_fC(aabb, a3_color);
    }
}

int dk2::MyNBitTexture::f8_5C08E0(AABB *aabb, Bgraf a3_color) {
    int w = AABB_getWidth(aabb);
    int h = AABB_getHeight(aabb);
    this->v_f20(aabb->minX, aabb->minY, w - 1, a3_color);
    this->v_f24(aabb->maxX - 1, aabb->minY, h - 1, a3_color);
    this->v_f20(aabb->minX + 1, aabb->maxY - 1, w - 1, a3_color);
    return this->v_f24(aabb->minX, aabb->minY + 1, h - 1, a3_color);
}

unsigned __int8 dk2::MyNBitTexture::f10_5C1400(int a2, int a3, int a4, Bgraf color) {
    if ((g_MyNBitTexture_surf_f0 & 4) != 0) {
        return (unsigned __int8) this->v_f14(a2, a3, a4, color);
    } else {
        return this->v_f18(a2, a3, a4, color);
    }
}


char __cdecl dk2::static_MyNBitTexture_f0(int x, int y, Bgraf color) {
    return pMyNBitTexture->v_f0(x, y, color);
}

int __cdecl dk2::static_MyNBitTexture_f4(AABB *a1, Bgraf a2_color) {
    if (!AABB_isIntersectsWithScreen(a1)) return 0;
    return pMyNBitTexture->v_f4(a1, a2_color);
}

int __cdecl dk2::static_MyNBitTexture_f8(AABB *a1, Bgraf a2) {
    if (!AABB_isIntersectsWithScreen(a1)) return 0;
    return pMyNBitTexture->v_f8(a1, a2);
}

int __cdecl dk2::static_MyNBitTexture_f1C(int a1, int a2, int a3, int a4, Bgraf a5_color) {
    AABB v6;
    v6.minX = a1;
    v6.minY = a2;
    v6.maxX = a3;
    v6.maxY = a4;
    if (!AABB_isIntersectsWithScreen(&v6)) return 0;
    return pMyNBitTexture->v_f1C(a1, a2, a3, a4, a5_color);
}

__int16 __cdecl dk2::static_MyNBitTexture_f20(int a1, int a2, int a3, Bgraf a4_color) {
    AABB v6;
    v6.minX = a1;
    v6.minY = a2;
    v6.maxX = a3 + a1;
    v6.maxY = a2 + 1;
    if (!AABB_isIntersectsWithScreen(&v6)) return 0;
    return (uint16_t) pMyNBitTexture->v_f20(a1, a2, a3, a4_color);
}

int __cdecl dk2::static_MyNBitTexture_f24(int a1, int a2, int a3, Bgraf a4_color) {
    AABB v5;
    v5.minX = a1;
    v5.minY = a2;
    v5.maxX = a1 + 1;
    v5.maxY = a3 + a2;
    if (!AABB_isIntersectsWithScreen(&v5)) return 0;
    return pMyNBitTexture->v_f24(a1, a2, a3, a4_color);
}

int __cdecl dk2::static_MyNBitTexture_f10(int a1_mouseX, int a2_mouseY, int a3, Bgraf color) {
    AABB v5;
    v5.minY = a2_mouseY - a3;
    v5.minX = a1_mouseX - a3;
    v5.maxX = a3 + a1_mouseX;
    v5.maxY = a3 + a2_mouseY;
    if (!AABB_isIntersectsWithScreen(&v5)) return 0;
    return pMyNBitTexture->v_f10(a1_mouseX, a2_mouseY, a3, color);
}

BYTE *__cdecl dk2::MyNBitTexture_f14_renderIfInScreen(int centerX, int centerY, int size, Bgraf a4) {
    AABB v5;
    v5.minY = centerY - size;
    v5.minX = centerX - size;
    v5.maxX = size + centerX;
    v5.maxY = size + centerY;
    if (!AABB_isIntersectsWithScreen(&v5)) return 0;
    return pMyNBitTexture->v_f14(centerX, centerY, size, a4);
}

char __cdecl dk2::static_MyNBitTexture_f18(int a1, int a2, int a3, Bgraf color) {
    AABB v6;
    v6.minY = a2 - a3;
    v6.minX = a1 - a3;
    v6.maxX = a3 + a1;
    v6.maxY = a3 + a2;
    if (!AABB_isIntersectsWithScreen(&v6)) return 0;
    return (uint8_t) pMyNBitTexture->v_f18(a1, a2, a3, color);
}

int __cdecl dk2::MyNBitTexture_fC(AABB *a1, Bgraf a2) {
    if (!AABB_isIntersectsWithScreen(a1)) return 0;
    return (uint8_t) pMyNBitTexture->v_fC(a1, a2);
}

char __cdecl dk2::static_MyNBitTexture_f30(int a1, int a2, const char *a3_text, Bgraf a4_color) {
    return pMyNBitTexture->v_f30(a1, a2, a3_text, a4_color);
}

void __cdecl dk2::static_MyNBitTexture_f38(int a1, int a2, int a3) {
    pMyNBitTexture->v_f38(a1, a2, (unsigned __int8 **)a3);
}

void __cdecl dk2::static_MyNBitTexture_f3C(int a1, int a2, int a3, int a4, char a5) {
    pMyNBitTexture->v_f3C(a1, (char **)a2, a3, a4, a5);
}


