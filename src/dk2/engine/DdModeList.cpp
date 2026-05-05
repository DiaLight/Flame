//
// Created by DiaLight on 1/10/2026.
//

#include "dk2/engine/DdModeList.h"
#include "dk2/dk2_memory.h"
#include "game_engine.h"

namespace dk2 {

    void DdModeList::constructor() {
        this->last = (DdModeListItem*) this;
        this->next = (DdModeListItem*) &this->prev;
        this->prev = NULL;
    }
    DdModeListItem* DdModeList::head() {
        return &this->prev != (DdModeListItem**)this->next ? this->next : NULL;
    }
    DdModeListItem* DdModeList::insert(DdModeListItem* _last, DdModeListItem* newItem) {
        DdModeListItem *_next = _last->next;
        newItem->prev = _last;
        newItem->next = _next;
        _last->next->prev = newItem;
        _last->next = newItem;
        return _last;
    }
    void DdModeList::destroy() {
        for (DdModeListItem* i = this->head(); i; i = this->head()) {
            i->prev->next = i->next;
            i->next->prev = i->prev;
            dk2::operator_delete(i);
        }
    }
    bool DdModeList::callback(LPDDSURFACEDESC lpDesc) {
        auto* item = (DdModeListItem*) dk2::operator_new(sizeof(DdModeListItem));
        if (!item) return false;
        item->dwWidth = lpDesc->dwWidth;
        item->dwHeight = lpDesc->dwHeight;
        item->dwRGBBitCount = lpDesc->ddpfPixelFormat.dwRGBBitCount;
        this->insert(this->last, item);
        return true;
    }

    int *DdModeList::collect(int *pstatus, LPDIRECTDRAW lpDD, int useWindowContext, HWND hWnd) {
        LPDDENUMMODESCALLBACK lpCallback = [](LPDDSURFACEDESC lpDesc, LPVOID lpContext) -> HRESULT {
            if(!((DdModeList*) lpContext)->callback(lpDesc)) return DDENUMRET_CANCEL;
            return DDENUMRET_OK;
        };
        if (useWindowContext) {
            HWND hWindow = hWnd;
            if (!hWnd) {
                BullfrogWindow_registerClass();
                hWindow = CreateWindowExA(
                    0, g_bullfrogClassName, "ModeList",
                    0x80000000, 0, 0,
                    1280, 1024,
                    NULL, NULL, getHInstance(), NULL);
                if (!hWindow) return *pstatus = -1, pstatus;
            }
            if (lpDD->SetCooperativeLevel(hWindow, 0x55)) {
                return *pstatus = -1, pstatus;
            }
            lpDD->EnumDisplayModes(0, NULL, this, lpCallback);
            lpDD->SetCooperativeLevel(hWindow, 8);
            if (!hWnd) DestroyWindow(hWindow);
        } else {
            lpDD->EnumDisplayModes(0, NULL, this, lpCallback);
        }
        return *pstatus = 0, pstatus;
    }

    DdModeList DdModeList::instance;

}
