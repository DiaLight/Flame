//
// Created by DiaLight on 01.07.2024.
//
#include <dk2/dk2_memory.h>
#include <patches/logging.h>

#include "dk2/MyBBase673E70.h"
#include "dk2/MyBUnk673FD8.h"
#include "dk2/MyGame.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/MyObj673FD4.h"
#include "dk2/MyUnk673FD0.h"
#include "dk2/MyUnk67457C.h"
#include "dk2/button/CTextBox.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/game_version_patch.h"
#include "patches/micro_patches.h"
#include "patches/replace_heap.h"
#include "weanetr_dll/MLDPlay.h"


int32_t dk2::MyGame::isOsCompatible() {
    if(patch::modern_windows_support::enabled) {
        return !dk2::isOsVersionGE(11, 0, 0);
    }
    return !isOsVersionGE(6, 0, 0);
}

void dk2::resolveDk2HomeDir() {
    if(patch::use_cwd_as_dk2_home_dir::enabled) {
        char tmp[MAX_PATH];
        DWORD len = GetCurrentDirectoryA(MAX_PATH, tmp);
        strcpy(tmp + len, "\\");
        // patch::log::dbg("replace exe dir path1: %s -> %s", dk2::dk2HomeDir, tmp);
        strcpy(dk2::dk2HomeDir, tmp);
        return;
    }
    const char *CommandLineA = GetCommandLineA();
    _strncpy(pathBuf, CommandLineA, 259u);
    char firstChar = pathBuf[0];
    pathBuf[259] = 0;
    char sepChar = ' ';
    if ( pathBuf[0] == '"' ) {
        signed int idx = 0;
        sepChar = '"';
        unsigned int len = strlen(pathBuf) + 1;
        if ( (int)(len - 1) > 0 ) {
            do {
                pathBuf[idx] = pathBuf[idx + 1];
                ++idx;
            } while ( idx < (int)(len - 1) );
            firstChar = pathBuf[0];
        }
    }
    char *pos = pathBuf;
    if ( firstChar ) {
        char curChar = firstChar;
        do
        {
            if ( curChar == sepChar )
                break;
            curChar = *++pos;
        }
        while ( curChar );
    }
    *pos = 0;
    char *sep1Pos = strrchr(pathBuf, '/');
    char *sep2Pos = strrchr(pathBuf, '\\');
    char **pSepPos = &sep2Pos;
    if ( sep2Pos <= sep1Pos ) pSepPos = &sep1Pos;
    char *sepPos = *pSepPos;
    if ( sepPos ) {
        sepPos[1] = 0;
        setExeDirPath(pathBuf);
    }
}


void __cdecl dk2::CTextBox_renderVersion(dk2::CTextBox *textBox, CFrontEndComponent *frontend) {
    AABB area;
    textBox->getScreenAABB(&area);
    AABB scaled;
    scaled = *frontend->cgui_manager.scaleAabb_2560_1920(&scaled, &area);

    uint8_t __buf[sizeof(MyTextRenderer)];
    MyTextRenderer &renderer = *(MyTextRenderer *) &__buf;
    renderer.constructor();
    int status;
    renderer.selectMyCR(&status, 0);
    renderer.selectMyTR(&status, 2);
    wchar_t wstring[64];
    if(char *version = patch::game_version_patch::getFileVersion()) {
        swprintf(wstring, L"%S", version);
    } else {
        swprintf(wstring, L"V%lu.%lu", g_majorVersion, g_minorVersion);
    }
    uint8_t mbstring[64];
    UniToMb_convert(wstring, mbstring, 64);
    renderer.renderText(&status, &scaled, mbstring, &g_FontObj2_instance, NULL);
    renderer.destructor();
}

int __cdecl dk2::cmd_dumpPlayer(int a1, int a2) {
    WeaNetR_instance.getPlayerInfo();
    if ( *(DWORD *)(a2 + 28) >= WeaNetR_instance.joinedPlayersCount ) {
        ProbablyConsole_instance.appendOutput("Invaliud Player");
        return 1;
    } else {
        // DestroySession
        if ( WeaNetR_instance.mldplay->DumpPlayer(*(DWORD *)(a2 + 28)) )
            ProbablyConsole_instance.appendOutput("Player Dumped");
        else
            ProbablyConsole_instance.appendOutput("Error!");
        return 1;
    }
}

int dk2::cmd_Game() {  // there should be args
    char msgData = 0x63;
    if (!WeaNetR_instance.sendGuaranteedData(&msgData, 1u, 0xFFFFu)) {
        ProbablyConsole_instance.appendOutput("Unable to Send Guaranteed Data");
        return 0;
    }
    ProbablyConsole_instance.appendOutput("Send Guaranteed Data success");
    WeaNetR_instance.mldplay->EnableNewPlayers(0);
    return 1;
}

int dk2::MyUnk67457C::sub_61C090() {
    if (patch::while_without_syscall_fix::enabled) {
        SwitchToThread();
    }
    return this->flags & 2;
}

void dk2::MyUnk673FD0::destructor() {
    *(void **) this = &MyUnk673FD0::vftable;
    this->threadExit = 1;
    InterlockedExchange((LONG volatile *) &this->threadWorking, 1);
    while (!this->threadStopped) {
        if (patch::while_without_syscall_fix::enabled) {
            SwitchToThread();
        }
    }
    MyBUnk673FD8 *arr0 = this->pMyBUnk673FD8_arrx12;
    if (arr0) {
        arr0->v_f8_array_delete(3);
    }
    dk2::operator_delete(this->pMyBUnk673FD8_arrx12_f44);
    for (MyBBase673E70 *cur = this->list_last_24; cur; cur = cur->prev ) {
        cur->v_f24_cleanup();
    }
    for (MyObj673FD4 *cur = this->arr100_first; cur; cur = this->arr100_first) {
        this->arr100_first = cur->next;
        dk2::operator_delete(cur);
    }
    DeleteCriticalSection(&this->critSec);
    dk2::operator_delete(this->parr_34);
}

void *dk2::___onexitinit() {
    int maxOnExitCalls = 32;
    if(patch::buffer_overrun_fix::enabled) {
        maxOnExitCalls *= 4;
    }
    DWORD *onexit_ptr = (DWORD *) _malloc_1(maxOnExitCalls * 4);
    _onexit_list_start = onexit_ptr;
    if ( !onexit_ptr )
        __amsg_exit(24);
    *onexit_ptr = 0;
    void *result = _onexit_list_start;
    _onexit_list_end = (int) _onexit_list_start;
    return result;
}


void *__cdecl dk2::__nh_malloc(size_t Size, int a2) {
    if(patch::replace_heap::enabled) {
        return (uint32_t *) patch::replace_heap::malloc(Size);
    }
    size_t v2_size = Size;
    if ( Size > 0xFFFFFFE0 )
        return 0;
    if ( !Size )
        v2_size = 1;
    while (true) {
        void *result = v2_size > 0xFFFFFFE0 ? 0 : __heap_alloc(v2_size);
        if ( result || !a2 )
            return result;
        if ( !__callnewh_(v2_size) )
            return NULL;
    }
}

void *__cdecl dk2::_malloc_1(size_t Size) {
    if(patch::replace_heap::enabled) {
        return patch::replace_heap::malloc(Size);
    }
    return __nh_malloc(Size, g_nhUnk_7A57BC);
}

void __cdecl dk2::_free(void *ptr) {
    if(patch::replace_heap::enabled) {
        patch::replace_heap::free(ptr);
        return;
    }
    if (void *v1_ptr = ptr) {
        __lock(9);
        void **v3;
        BYTE *v2 = (BYTE *) ___sbh_find_block(v1_ptr, &v3, (unsigned int *)&ptr);
        if ( v2 ) {
            ___sbh_free_block(v3, ptr, v2);
            __unlock(9);
        } else {
            __unlock(9);
            HeapFree(hHeap, 0, v1_ptr);
        }
    }
}

namespace dk2 {
    void sbhMemcpy(void *dst, void *src, void* v6_sbhPtr, size_t Size, void** v10, DWORD* v9) {
        unsigned int _size = 16 * *(unsigned __int8*) v6_sbhPtr;
        if (_size >= Size)
            _size = Size;
        memcpy(dst, src, _size);
        ___sbh_free_block(v10, v9, v6_sbhPtr);
    }
}

void *__cdecl dk2::_realloc(void *ptr, size_t Size) {
    if (patch::replace_heap::enabled) {
        return patch::replace_heap::realloc(ptr, Size);
    }
    if (!ptr)
        return _malloc_1(Size);
    if (!Size) {
        free(ptr);
        return NULL;
    }
    if (Size <= 0xFFFFFFE0) {
        Size = (Size + 15) & 0xFFFFFFF0;
    }
    while (true) {
        void* v5_newPtr = NULL;
        if (Size <= 0xFFFFFFE0) {
            __lock(9);
            DWORD* v9;
            void** v10;
            void* v6_sbhPtr = (void*) ___sbh_find_block(ptr, &v10, (unsigned int*) &v9);
            if (!v6_sbhPtr) {
                __unlock(9);
                v5_newPtr = HeapReAlloc(hHeap, 0, ptr, Size);
            } else {
                if (Size < g_sbh_size) {
                    if (___sbh_resize_block(v10, v9, v6_sbhPtr, Size >> 4)) {
                        v5_newPtr = ptr;
                    } else {
                        v5_newPtr = ___sbh_alloc_block(Size >> 4);
                        if (v5_newPtr != nullptr) {
                            sbhMemcpy(v5_newPtr, ptr, v6_sbhPtr, Size, v10, v9);
                        }
                    }
                }
                if (!v5_newPtr) {
                    v5_newPtr = HeapAlloc(hHeap, 0, Size);
                    if (v5_newPtr) {
                        sbhMemcpy(v5_newPtr, ptr, v6_sbhPtr, Size, v10, v9);
                    }
                }
                __unlock(9);
            }
        }
        if (v5_newPtr || !g_nhUnk_7A57BC)
            return v5_newPtr;
        void* result = (void*) __callnewh_(Size);
        if (!result)
            return NULL;
    }
}

void *__cdecl dk2::_calloc(size_t Count, size_t Size) {
    if (patch::replace_heap::enabled) {
        return patch::replace_heap::malloc(Count * Size);
    }
    unsigned int v2_totalSize = Count * Size;
    if (Count * Size <= 0xFFFFFFE0) {
        if (v2_totalSize)
            v2_totalSize = (v2_totalSize + 15) & 0xFFFFFFF0;
        else
            v2_totalSize = 16;
    }
    while (true) {
        void* v3_ptr = NULL;
        if (v2_totalSize <= 0xFFFFFFE0) {
            if (v2_totalSize <= g_sbh_size) {
                __lock(9);
                v3_ptr = ___sbh_alloc_block(v2_totalSize >> 4);
                __unlock(9);
                if (v3_ptr != nullptr) {
                    memset(v3_ptr, 0, v2_totalSize);
                    return v3_ptr;
                }
            }
            v3_ptr = HeapAlloc(hHeap, 8u, v2_totalSize);
        }
        if (v3_ptr || !g_nhUnk_7A57BC) return v3_ptr;
        void* result = (void*) __callnewh_(v2_totalSize);
        if (!result) return NULL;
    }
}

size_t __cdecl dk2::__msize(void *ptr) {
    if (patch::replace_heap::enabled) {
        return patch::replace_heap::size(ptr);
    }
    __lock(9);
    unsigned int v4;
    void **v5;
    auto *v1 = (unsigned __int8 *)___sbh_find_block(ptr, &v5, &v4);
    if (v1) {
        size_t v2 = 16 * *v1;
        __unlock(9);
        return v2;
    } else {
        __unlock(9);
        return HeapSize(hHeap, 0, ptr);
    }
}

