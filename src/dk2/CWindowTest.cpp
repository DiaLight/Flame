//
// Created by DiaLight on 9/19/2025.
//
#include "dk2/CWindowTest.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/logging.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"


void dk2::CWindowTest::reallocBackSurfaceToWindowSize() {
    if ( (client_rect_initialized & 1) == 0 ) {
        client_rect.left = 0;
        client_rect_initialized |= 1u;
        client_rect.top = 0;
        client_rect.right = 0;
        client_rect.bottom = 0;
//        atexit(nullsub_9);
    }
    RECT Rect;
    GetClientRect(this->hWnd, &Rect);
    if(patch::big_resolution_fix::enabled) {  // patch from Ember project
//        int width = Rect.right - Rect.left;
//        int height = Rect.bottom - Rect.top;
//        if (width != api::g_width || height != api::g_height) {
//            printf("FIX: GetClientRect: l=%d, t=%d, r=%d, b=%d => create surf %dx%d but game expect to work with buffers %dx%d\n",
//                   Rect.left, Rect.top, Rect.right, Rect.bottom,
//                   width, height,
//                   api::g_width, api::g_height
//            );
//            Rect.right = Rect.left + api::g_width;
//            Rect.bottom = Rect.top + api::g_height;
//        }
    }
    if (client_rect.left != Rect.left
        || client_rect.right != Rect.right
        || client_rect.top != Rect.top
        || client_rect.bottom != Rect.bottom) {
        GetClientRect(this->hWnd, &Rect);
        client_rect = Rect;
        if (this->pCurOffScreenSurf) {
            int status;
            MyDdSurface_release(&status, &this->pCurOffScreenSurf->dd_surf);
            this->pCurOffScreenSurf = NULL;
        }
    }
    if (!this->pCurOffScreenSurf) {
        GetClientRect(this->hWnd, &Rect);
        int status;
        static_assert((DDSCAPS_VIDEOMEMORY | DDSCAPS_3DDEVICE) == 0x6000u);
        if (*MyDdSurface_createOffScreenSurface(
                &status,
                Rect.right - Rect.left,
                Rect.bottom - Rect.top,
                DDSCAPS_VIDEOMEMORY | DDSCAPS_3DDEVICE,
                &this->offScreenSurf.dd_surf) < 0)
            return;
        this->pCurOffScreenSurf = &this->offScreenSurf;
        setCurOffScreen(&this->offScreenSurf);
    }
}

