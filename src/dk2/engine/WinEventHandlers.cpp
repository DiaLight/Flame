//
// Created by DiaLight on 1/8/2026.
//

#include "dk2/inputs/WinEventHandlers.h"
#include "dk2/ControlKeysUpdater.h"
#include "dk2/MyCb6723D0.h"
#include "dk2/MyDxInputState.h"
#include "dk2/MyDxKeyboard.h"
#include "dk2/MyDxMouse.h"
#include "dk2/MyLList_WinEventCb_entry.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/dk2_memory.h"
#include "dk2/inputs/Event0_cursorDraw5.h"
#include "dk2/inputs/Event0_unk6.h"
#include "dk2/inputs/Event0_winShown7.h"
#include "dk2/inputs/Event5_keyboard.h"
#include "dk2/inputs/MyCallback.h"
#include "dk2/inputs/MyCbHandle.h"
#include "dk2/inputs/MyControlKeysCb.h"
#include "dk2/inputs/MyDxInputStateCb.h"
#include "dk2/inputs/MyMouseCb.h"
#include "dk2/inputs/WinEventCb.h"
#include "dk2_functions.h"
#include "dk2_globals.h"


namespace dk2 {

    int MyDxInputManagerCb_idxs_[] {0, 6};  // MyDxInputManagerCb::call
    int MyDxInputStateCb_idxs_[] {5, 6};  // MyDxInputStateCb::call
    int MyCb6723D0_idxs_[] {0, 1, 6};  // MyCb6723D0::call
    int MyControlKeysCb_idxs_[] {5, 6};  // MyControlKeysCb::call
    int MyMouseCb_idxs_[] {0, 6};  // MyMouseCb::call


    // all completely decompiled
    // 0:  // complete
    //   f0=4: {f0: 4, f4: isWinActive}  // 005B50C4 BullfrogWindow_proc
    //   f0=5: {f0: 5, f4: 0}  // 005B419A ge_ddReleaseSurfaces
    //   f0=6: {f0: 6, f4: 0}  // 005B4390 ge_dk2dd_init
    //   f0=7: Event0_winShown7 {f0: 7, f4: width, f8: height, fC: bpp, f10: isdevAcquireAnyTime 0|1}
    //     f10=0: 005B4390 ge_dk2dd_init
    //     f10=1: 00556524 CWindowTest_probably_do_show_window_ev0_7
    // 1: {f0: 0|1|2|3, f4: MyDdSurfaceEx *}  // complete
    //   f0=0:
    //     0055628C CWindowTest_copyToWindowSurf
    //     005B4B84 copyToFullscreenSurf
    //   f0=1:
    //     0055630D CWindowTest_copyToWindowSurf
    //     005B4CAF copyToFullscreenSurf
    //   f0=2: 005B4B2D copyToFullscreenSurf
    //   f0=3: 005B4B6B copyToFullscreenSurf
    // 5: Event5_Keyboard {f0: 11, MyDxDevice *}  // complete
    //   f0=11: 005BC42D DxDevice_updateCoopLevelAndSignal_ev5


    void callWinEvent_ev0_ty4(int isActivated) {  // 005B50C4 BullfrogWindow_proc
        Event0_winShown7 v7;
        v7.eventType = 4;
        v7.width = isActivated;
        WinEventHandlers_instance.callList(0, &v7);
    }
    void callWinEvent_ev0_ty5(int f4) {  // 005B419A ge_ddReleaseSurfaces
        Event0_cursorDraw5 v0;
        v0.eventType = 5;
        v0.f4 = f4;
        WinEventHandlers_instance.callList(0, &v0);
    }
    void callWinEvent_ev0_ty6(int f4) {  // 005B4390 ge_dk2dd_init
        // create DD event
        Event0_unk6 Event6;
        Event6.eventType = 6;
        Event6.f4 = f4;
        WinEventHandlers_instance.callList(0, &Event6);
    }
    void callWinEvent_ev0_ty7_aq0(uint32_t width, uint32_t height, uint32_t displayBitness) {  // 005B4390 ge_dk2dd_init
        // send window shown event
        Event0_winShown7 Event;
        Event.eventType = 7;
        Event.width = width;
        Event.height = height;
        Event.display_bitnes = displayBitness;
        Event.isdevAcquireAnyTime = 0;
        WinEventHandlers_instance.callList(0, &Event);
    }
    void callWinEvent_ev0_ty7_aq1(uint32_t width, uint32_t height, uint32_t displayBitness) {  // 00556524 CWindowTest_probably_do_show_window_ev0_7
        // send window shown event
        Event0_winShown7 Event;
        Event.eventType = 7;
        Event.width = width;
        Event.height = height;
        *(BYTE*) &Event.display_bitnes = displayBitness;
        Event.isdevAcquireAnyTime = 1;
        WinEventHandlers_instance.callList(0, &Event);
    }

    void callWinEvent_ev1_ty0(MyDdSurfaceEx *surf) {
        // 0055628C CWindowTest_copyToWindowSurf
        // 005B4B84 copyToFullscreenSurf
        struct {
            int v7;
            MyDdSurfaceEx *surf;
        } arg {0, surf};
        WinEventHandlers_instance.callList(1, &arg);
    }
    void callWinEvent_ev1_ty1(MyDdSurfaceEx *surf) {
        // 0055630D CWindowTest_copyToWindowSurf
        // 005B4CAF copyToFullscreenSurf
        struct {
            int v7;
            MyDdSurfaceEx *surf;
        } arg {1, surf};
        WinEventHandlers_instance.callList(1, &arg);
    }
    void callWinEvent_ev1_ty2(MyDdSurfaceEx *surf) {  // 005B4B2D copyToFullscreenSurf
        struct {
            int v7;
            MyDdSurfaceEx *surf;
        } arg {2, surf};
        WinEventHandlers_instance.callList(1, &arg);
    }
    void callWinEvent_ev1_ty3(MyDdSurfaceEx *surf) {  // 005B4B6B copyToFullscreenSurf
        struct {
            int v7;
            MyDdSurfaceEx *surf;
        } arg {3, surf};
        WinEventHandlers_instance.callList(1, &arg);
    }

    void callWinEvent_ev5_ty11(MyDxDevice *dev) {  // 005BC42D DxDevice_updateCoopLevelAndSignal_ev5
        Event5_keyboard v5;
        v5.v11 = 11;
        v5.dev = dev;
        WinEventHandlers_instance.callList(5, &v5);
    }

}



void dk2::MyControlKeysCb::call(int listNum, void *arg) {  // listNum=5
    auto *kb = (Event5_keyboard *) arg;
    auto *up = (ControlKeysUpdater *)((char *) this - 0xC);
    up->call(kb->dev);
}

void dk2::MyDxInputStateCb::call(int listNum, void *arg) {  // listNum=5
    auto *a3 = (Event5_keyboard *) arg;
    auto *st = (MyDxInputState *)((char *) this - 0xC);
    st->updateKeysState(a3->dev);
}

void dk2::MyMouseCb::call(int listNum, void *arg) {  // listNum=0
    auto* evt = (Event0_winShown7*) arg;
    if (evt->eventType == 7) {
        auto* mmu = (MyMouseUpdater*) ((char*) this - 0x64);
        AABB a2 {0, 0, evt->width, evt->height};
        mmu->call(&a2);
    }
}

void dk2::MyCb6723D0::call(int listNum, void *arg) {  // listNum=[0, 1]
    auto *evt = (Event0_winShown7 *) arg;
    if (listNum == 0) {
        if (evt->eventType == 5) {
            this->inputCursor.Event0_5Handler();
        } else if (evt->eventType == 7) {
            this->inputCursor.Event0_7Handler_updateAabb();
        }
    } else if (listNum == 1) {
        switch (evt->eventType) {
        case 0:
        case 2:
            this->inputCursor.Event1_2Handler_updateCursor();
            break;
        case 1:
        case 3:
            this->inputCursor.Event1_3Handler();
            break;
        default:
            return;
        }
    }
}

void dk2::MyDxInputManagerCb::call(int listNum, void *arg) {  // listNum=0
    int status;
    auto *evt = (Event0_winShown7 *) arg;
    switch (evt->eventType) { // window activated/deactivated
    case 4:  // activate message
        OutputDebugStringA("Activate Message Recieved\n");
        ShowCursor(evt->width == 0); // show if not activated
        if (!this->f50_createDD_state && evt->width)
            this->onWindowActivated(&status, evt->width);
        break;
    case 6:
        this->f50_createDD_state = 1;
        break;
    case 7:  // update coop level
        if (evt->isdevAcquireAnyTime) {
            if (MyDxKeyboard* dxKeyboard = this->f54_pdxKeyboard) {
                static_assert((DISCL_NONEXCLUSIVE | DISCL_BACKGROUND) == 0xA);
                dxKeyboard->dx_device.setCoopLevel(&status, DISCL_NONEXCLUSIVE | DISCL_BACKGROUND);
            }
            if (MyDxMouse* dxmouse = this->f58_pdxmouse) {
                static_assert((DISCL_NONEXCLUSIVE | DISCL_BACKGROUND) == 0xA);
                dxmouse->dx_device.setCoopLevel(&status, DISCL_NONEXCLUSIVE | DISCL_BACKGROUND);
            }
        } else {
            if (MyDxKeyboard* dxKeyboard = this->f54_pdxKeyboard) {
                static_assert((DISCL_NONEXCLUSIVE | DISCL_FOREGROUND) == 6);
                dxKeyboard->dx_device.setCoopLevel(&status, DISCL_NONEXCLUSIVE | DISCL_FOREGROUND);
            }
            if (MyDxMouse* dxmouse = this->f58_pdxmouse) {
                static_assert((DISCL_EXCLUSIVE | DISCL_FOREGROUND) == 5);
                dxmouse->dx_device.setCoopLevel(&status, DISCL_EXCLUSIVE | DISCL_FOREGROUND);
            }
        }
        this->updateCoopLevelAndSignal(&status);
        this->f50_createDD_state = 0;
        break;
    }
}


namespace dk2 {

    void __stdcall MyCallback_call(int listNum, void *arg, void *obj) {
        auto *mcb = (MyCallback *) obj;
        mcb->v_call(listNum, arg);
    }

    void __stdcall static_MyWindow_Event07_cb(int listNum, void *arg, void *obj) {  // listNum=0
        auto *evarg = (Event0_winShown7 *) arg;
        auto *window = (MyWindow *) obj;
        if ( evarg->eventType == 4 ) return;  // window active event
        if ( evarg->eventType == 6 ) {  // create DD event
            g_isCreateDDState = 1;
        } else if ( evarg->eventType == 7 ) {  // window shown event
            g_isCreateDDState = 0;
        }
    }

}

void dk2::MyCbHandle::add_MyCallback(uint32_t *idxList, MyCallback *cbObj) {
    this->release_MyCallback();
    this->callbackObj = cbObj;
    this->callbackIdxList = idxList;
    for (uint32_t* cur = idxList; *cur != 6; ++cur) {
        WinEventHandlers_instance.addHandler(
            *cur, MyCallback_call, this->callbackObj);
    }
}

void dk2::MyCbHandle::release_MyCallback() {
    if (!this->callbackIdxList) return;
    for (; *this->callbackIdxList != 6; this->callbackIdxList++) {
        WinEventHandlers_instance.removeHandler(
            *this->callbackIdxList, MyCallback_call, this->callbackObj);
    }
    this->callbackIdxList = NULL;
    this->callbackObj = NULL;
}


void dk2::WinEventHandlers::addHandler(
    int listNum,
    void (__stdcall *fun)(int, void *, void *),
    void *obj
) {
    CRITICAL_SECTION* critSec = this->crit_section;
    EnterCriticalSection(critSec);
    if (listNum != 6) {
        WinEventCb* cb;
        {
            WinEventCb* v6_cb = (WinEventCb*) dk2::operator_new(sizeof(WinEventCb));
            if (v6_cb) {
                v6_cb->fun = fun;
                v6_cb->obj_0 = obj;
                cb = v6_cb;
            } else {
                cb = NULL;
            }
        }
        MyLList_WinEventCb_entry* entry = (MyLList_WinEventCb_entry*) dk2::operator_new(sizeof(MyLList_WinEventCb_entry));
        if (entry) {
            entry->value = cb;
            entry->next = NULL;
            entry->prev = NULL;
        } else {
            entry = NULL;
        }
        {  // push_back
            MyLList_WinEventCb* llist = &this->arr[listNum];
            entry->prev = llist->last;
            if (MyLList_WinEventCb_entry* f8_last = llist->last) {
                f8_last->next = entry;
            } else {
                llist->first = entry;
            }
            llist->last = entry;
            ++llist->count;
        }
    }
    LeaveCriticalSection(critSec);
}


void dk2::WinEventHandlers::callList(int arrNum, void *arg) {
    CRITICAL_SECTION* f60_crit_section = this->crit_section;
//    EnterCriticalSection(f60_crit_section);
    {  // patch
        if(f60_crit_section) EnterCriticalSection(f60_crit_section);
    }
    if (arrNum != 6) {
        for(auto* cur = this->arr[arrNum].first; cur; cur = cur->next) {
            WinEventCb* cb = cur->value;
            if (auto *fun = cb->fun) {
                fun(arrNum, arg, cb->obj_0);
            }
        }
    }
    if (f60_crit_section) {
        LeaveCriticalSection(f60_crit_section);
    }
}

void dk2::WinEventHandlers::removeHandler(
    int listNum,
    void (__stdcall *fun)(int, void *, void *),
    void *obj) {
    if (!this->crit_section) return;
    CRITICAL_SECTION* critSec = this->crit_section;
    EnterCriticalSection(critSec);
    if (listNum != 6) {
        MyLList_WinEventCb* llist = &this->arr[listNum];
        MyLList_WinEventCb_entry *next = NULL;
        for (auto *cur = llist->first; cur; cur = next) {
            next = cur->next;

            WinEventCb* cb = cur->value;
            if (cb->fun != fun) continue;
            if (obj && cb->obj_0 != obj) continue;

            {  // erase
                auto* cur_next = cur->next;
                auto* cur_prev = cur->prev;
                if (cur == llist->first) {
                    llist->first = cur_next;
                } else {
                    cur_prev->next = cur_next;
                }

                if (cur == llist->last) {
                    llist->last = cur_prev;
                } else {
                    cur_next->prev = cur_prev;
                }

                --llist->count;
            }
            dk2::operator_delete(cur);
            dk2::operator_delete(cb);
        }
    }
    LeaveCriticalSection(critSec);
}

void dk2::WinEventHandlers::clear() {
    LPCRITICAL_SECTION critSec = this->crit_section;
    EnterCriticalSection(critSec);

    for (int i = 0; i < 6; ++i) {
        MyLList_WinEventCb* llist = &this->arr[i];
        while (llist->count) {
            auto* cur = llist->first;
            WinEventCb* cb;
            if (cur) {
                auto* cur_next = cur->next;
                llist->first = cur_next;
                if (cur_next)
                    cur_next->prev = NULL;
                else
                    llist->last = NULL;
                WinEventCb* f0_value = cur->value;
                --llist->count;
                dk2::operator_delete(cur);
                cb = f0_value;
            } else {
                cb = NULL;
            }
            dk2::operator_delete(cb);
        }
    }
    LeaveCriticalSection(critSec);
}

