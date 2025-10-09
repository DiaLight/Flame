//
// Created by DiaLight on 9/19/2025.
//
#include "dk2/CWindowTest.h"
#include "dk2/Event0_winShown7.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/logging.h"


int *dk2::CWindowTest::probably_do_show_window_ev0_7(int *pstatus, AABB *rect) {
    int status;

    if (this->f5C) {
        if ( this->pCurOffScreenSurf ) {
            MyDdSurface_release(&status, &this->pCurOffScreenSurf->dd_surf);
            this->pCurOffScreenSurf = NULL;
        }
        this->f5C = 0;
        BullfrogWindow_destroy();
        DestroyWindow(this->hWnd);

        GUID *guid = MyGame_instance.getSelectedGuid();
        BullfrogWindow_create(&status, guid, 1, NULL, NULL);
    }

    AABB *v5_rect = rect;
    if ( *this->create(&status, rect) < 0 ) {
        patch::log::err("create window failed");
        *pstatus = -1;
        return pstatus;
    }

    if ( *this->recreateBullfrog(&status) < 0 ) {
        *pstatus = -1;
        return pstatus;
    }

    POINT screenPoint = {0, 0};
    ClientToScreen(this->hWnd, &screenPoint);

    AABB clientRect;
    clientRect.constructor();
    this->getClientRect(&clientRect);

    AABB res;
    clientRect.appendPoint(&res, &screenPoint);

//    color = init_color_32_8(a1_pstatus, 200, 200, 200, 0);  // 32: 0xFFC8C8C8, 8: 0
    __surface_init_blt(&status, &g_primarySurf, (RECT *) &clientRect, 0xFFC8C8C8, 0, 0);
    if (status < 0) {
        patch::log::err("__surface_init_blt failed");
        *pstatus = -1;
        return pstatus;
    }

    this->reallocBackSurfaceToWindowSize();
    if (this->pCurOffScreenSurf) {
        auto *desc = this->pCurOffScreenSurf->updateDesc();
        screenPoint.x = 0;
        screenPoint.y = 0;

        clientRect.constructor();
        clientRect.minY = screenPoint.y;
        clientRect.maxX = desc->dwWidth;
        clientRect.minX = screenPoint.x;
        clientRect.maxY = desc->dwHeight;
        __surface_init_blt(&status, this->pCurOffScreenSurf, (RECT *) &clientRect, 0xFFC8C8C8, 0, 0);
    }
    {
        // send window shown event
        Event0_winShown7 Event;
        Event.eventType = 7;
        Event.width = v5_rect->maxX - v5_rect->minX;
        Event.height = v5_rect->maxY - v5_rect->minY;
        *(BYTE *) &Event.display_bitnes = MyResources_instance.video_settings.display_bitnes;
        Event.isdevAcquireAnyTime = 1;
        WinEventHandlers_instance.callList(0, (int)&Event);
    }

    *pstatus = 0;
    return pstatus;
}


int *dk2::CWindowTest::recreateBullfrog(int *pstatus) {
    int status;
    BullfrogWindow_destroy();
    GUID *guid = MyGame_instance.getSelectedGuid();
    if (*BullfrogWindow_create(&status, guid, 0, this->hWnd, NULL) < 0) {
        patch::log::err("recreate dd window failed");
        *pstatus = -1;
        return pstatus;
    }
    HWND prevHWnd = getHWindow();
    setHWindow(this->hWnd);
    if (*dk2dd_init(&status, 640u, 480u, MyResources_instance.video_settings.display_bitnes, 0x58, NULL) < 0) {
        patch::log::err("dd init failed");
        *pstatus = -1;
        return pstatus;
    }
    setHWindow(prevHWnd);

    *pstatus = 0;
    return pstatus;
}


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

