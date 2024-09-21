//
// Created by DiaLight on 13.09.2024.
//

#include "bug_hunter.h"
#include "dk2_globals.h"
#include "StackLimits.h"
#include "LoadedModules.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <sstream>
#include <iostream>
#include <iomanip>

#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex32W(val) std::hex << std::setw(8) << std::setfill(L'0') << std::uppercase << (val) << std::dec
#define fmtHex(val) std::hex << std::uppercase << (val) << std::dec

uint32_t decodeVarint(uint8_t *&p) {
    uint32_t ret = 0;
    int i = 0;
    while (true) {
        uint8_t b = *p++;
        ret |= (b & 0x7F) << (7 * i++);
        if(!(b & 0x80)) break;
    }
    return ret;
}
int32_t decodeSignedVarint(uint8_t *&p) {
    uint32_t v = decodeVarint(p);
    if(v & 1) return -(v >> 1);
    return v >> 1;
}

enum MySpdType {
    MST_Ida = 0,
    MST_Fpo = 1,
    MST_Frm = 2
};
struct MySpd {
    size_t offs;
    int spd;
    DWORD ty;
    DWORD kind;
};

struct MyFpoFun {
    DWORD ptr;
    DWORD end;
    const char *name;
    std::vector<MySpd> spds;


    std::vector<MySpd>::iterator find_ge(DWORD offs) {
        return std::lower_bound(spds.begin(), spds.end(), offs, [](MySpd &bl, DWORD offs) {  // <=
            return bl.offs < offs;
        });
    }
};

extern "C" void *_fpomap_start = nullptr;
extern "C" void *_dkii_text_start = nullptr;
extern "C" void *_dkii_text_end = nullptr;
extern "C" void *_flame_text_start = nullptr;
extern "C" void *_flame_text_end = nullptr;
namespace bughunter {
    uint8_t *base = nullptr;
    uint8_t *end = nullptr;
    DWORD imageBase = 0;
    uint8_t *fpomap_start = nullptr;
    uint8_t *dkii_text_start = nullptr;
    uint8_t *dkii_text_end = nullptr;
    uint8_t *flame_text_start = nullptr;
    uint8_t *flame_text_end = nullptr;

    std::vector<MyFpoFun> fpomap;

    bool isAppCode(void *p) {
        if(dkii_text_start <= p && p < dkii_text_end) return true;
        if(flame_text_start <= p && p < flame_text_end) return true;
        return false;
    }
    inline bool isAppCode(DWORD p) { return isAppCode((void *) p); }

    std::vector<MyFpoFun>::iterator find_gt(DWORD ptr) {
        return std::upper_bound(fpomap.begin(), fpomap.end(), ptr, [](DWORD ptr, MyFpoFun &bl) {
            return ptr < bl.ptr;
        });
    }

    std::vector<MyFpoFun>::iterator find_le(DWORD ptr) {
        auto it = find_gt(ptr);
        if (it == fpomap.begin()) return fpomap.end();
        return it - 1;
    }
}

void resolveLocs() {
    uint8_t *base = (uint8_t *) GetModuleHandleA(NULL);
    bughunter::base = base;
    auto *pHeader = (PIMAGE_DOS_HEADER) base;
    if (pHeader->e_magic == IMAGE_DOS_SIGNATURE) {
        auto *header = (PIMAGE_NT_HEADERS) ((BYTE *) base + ((PIMAGE_DOS_HEADER) base)->e_lfanew);
        bughunter::imageBase = header->OptionalHeader.ImageBase;
        bughunter::end = bughunter::base + header->OptionalHeader.SizeOfImage;
    }
    // dirty hack to locate .fpomap section
    bughunter::fpomap_start = base + (uint32_t) (uint8_t *) &_fpomap_start;
    bughunter::dkii_text_start = base + (uint32_t) (uint8_t *) &_dkii_text_start;
    bughunter::dkii_text_end = base + (uint32_t) (uint8_t *) &_dkii_text_end;
    bughunter::flame_text_start = base + (uint32_t) (uint8_t *) &_flame_text_start;
    bughunter::flame_text_end = base + (uint32_t) (uint8_t *) &_flame_text_end;
}

void parseFpomap() {
    bughunter::fpomap.clear();
    uint8_t *p = bughunter::fpomap_start;
    size_t fposCount = decodeVarint(p);
//    printf("fposCount = %d\n", fposCount);
    DWORD va = 0;
    for (int i = 0; i < fposCount; ++i) {
        va += decodeVarint(p);
        size_t sz = decodeVarint(p);
        const char *name = (const char *) p;
        p += strlen(name) + 1;
        auto &fpoFun = bughunter::fpomap.emplace_back();
        fpoFun.ptr = (DWORD) (va - bughunter::imageBase + bughunter::base);
        fpoFun.end = fpoFun.ptr + sz;
        fpoFun.name = name;
//        printf("%08X-%08X %s\n", va, va + sz, name);
        size_t spdsCount = decodeVarint(p);
        for (int j = 0; j < spdsCount; ++j) {
            size_t offs = decodeVarint(p);
            int32_t spd = decodeSignedVarint(p);
            uint32_t ty = decodeVarint(p);
            uint32_t kind = decodeVarint(p);

            auto &mySpd = fpoFun.spds.emplace_back();
            mySpd.offs = offs;
            mySpd.spd = spd;
            mySpd.ty = ty;
            mySpd.kind = kind;
        }
    }
}

void controlOtherThreadsInCurProc(bool suspend) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD curPid = GetCurrentProcessId();
    DWORD curTid = GetCurrentThreadId();
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    for(bool b = Thread32First(h, &te); b; b = Thread32Next(h, &te)) {
        if (te.th32OwnerProcessID != curPid) continue;
        if (te.th32ThreadID == curTid) continue;
        if(HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID)) {
            if(suspend) {
                SuspendThread(hThread);
            } else {
                ResumeThread(hThread);
            }
            CloseHandle(hThread);
        }
    }
    CloseHandle(h);
}

void MyHideWindow(HWND hWnd) {
    char name[256];
    GetClassNameA(hWnd, name, sizeof(name));
    printf("%d hide classname: %s\n", GetCurrentThreadId(), name);
    BOOL res = ShowWindow(hWnd, SW_FORCEMINIMIZE);
    printf("%d res: %d\n", GetCurrentThreadId(), res);
}
void hideFullscreenWindow() {
    CreateThread(NULL, 0, [](LPVOID hWnd) -> DWORD { MyHideWindow((HWND) hWnd); return 0; }, dk2::hBullfrogWindow, 0, NULL);  // hide fullscreen window
}


struct StackFrame {

    bool isOld;
    DWORD eip;
    DWORD esp;
    DWORD ebp;

    // lib fields
    std::string libName;
    DWORD libBase = 0;
    std::string symName;
    DWORD symAddr = 0;

    // dk2 fields
    std::string dk2Name;
    std::wstring spinfo;
    bool error = false;

    void formatOneLine(std::wstringstream &ss);
    void format(std::wstringstream &ss);

    void onSuccess(const std::wstring &info) {
        spinfo = info;
        error = true;
    }
    void onError(const std::wstring &info) {
        spinfo = info;
        error = true;
    }

};

class StackWalker {

    LoadedModules &modules;
    StackLimits limits;
    CONTEXT ctx;
public:
    explicit StackWalker(LoadedModules &modules, CONTEXT &ctx) : modules(modules), ctx(ctx) {
        limits.resolve();
        modules.update();
    }

    void test() {
        // todo: describe how we get here
        // ebp can be invalid

        // validate context state
        if (!limits.contains(ctx.Esp)) {
            std::stringstream iss;
            iss << "bad esp=" << fmtHex32(ctx.Esp) << "\n";
            std::cout << iss.str();
//            formatError(iss, ctx, limits);
//            frame->onError(iss.str());
            return;
        }
        if (!limits.contains(ctx.Ebp)) {
            std::stringstream iss;
            iss << "bad ebp=" << fmtHex32(ctx.Ebp) << "\n";
            std::cout << iss.str();
//            formatError(iss, ctx, limits);
//            frame->onError(iss.str());
            return;
        }
        if(ctx.Ebp > ctx.Esp) {
            printf("ebp wasnt updated");
        }
        auto *bp = (uint32_t *) ctx.Ebp;
        ctx.Ebp = *bp++;
        if (ctx.Ebp != 0 && !limits.contains(ctx.Ebp)) {
            std::stringstream iss;
            iss << "bad ebp=" << fmtHex32(ctx.Ebp) << "\n";
            std::cout << iss.str();
//            formatError(iss, ctx, limits);
//            frame->onError(iss.str());
            return;
        }

        StackFrame frame;
        if(bughunter::isAppCode(ctx.Eip)) {
            auto it = bughunter::find_le(ctx.Eip);
            if(it != bughunter::fpomap.end() && ctx.Eip < it->end) {
                auto &fpo = *it;
                printf("%s+%X\n", fpo.name, ctx.Eip - fpo.ptr);
                auto it2 = fpo.find_ge(ctx.Eip - fpo.ptr);
                if (it2 != fpo.spds.end()) {
                    auto &ms = *it2;
                    const char *ty = "";
                    if(ms.ty == MST_Ida) {
                        ty = "ida";
                    } else if(ms.ty == MST_Fpo) {
                        ty = "fpo";
                    } else if(ms.ty == MST_Frm) {
                        ty = "frm";
                    }
                    std::cout << fmtHex32(fpo.ptr) << " " << fmtHex32(fpo.ptr + ms.offs) << " spd=" << fmtHex(ms.spd) << " " << ty << " kind=" << fmtHex(ms.kind) << std::endl;

                    ctx.Esp += ms.spd;
                    // try saved bp and ip
                    DWORD *p = (DWORD *) ctx.Esp;
                    for (int i = -2; i < 6; ++i) {
                        printf("%08X->%08X app=%d stk=%d\n", &p[i], p[i], bughunter::isAppCode(p[i]), limits.contains(p[i]));
                    }
                    //0019D46C->0019D480 app=0 stk=1
                    //0019D470->00829336 app=1 stk=0
                    //0019D474->00A80000 app=0 stk=0  <-
                    //0019D478->00000000 app=0 stk=0
                    //0019D47C->00000300 app=0 stk=0
                    //0019D480->0019D490 app=0 stk=1
                    //0019D484->0081725B app=1 stk=0
                    if(limits.contains(p[0])) {
                        if(bughunter::isAppCode(p[1])) {  // try
                            ctx.Esp += 8;
                            ctx.Eip += p[1];
                        } else {
                            printf("e1 %d\n", ms.ty);
                        }
                    } else {
                        printf("e2 %d\n", ms.ty);
                    }
                } else {
                    // try an empirical approach
                    printf("empirical approach2\n");
                }
            } else {
                // try an empirical approach
                printf("empirical approach\n");
            }
        } else {
            if (auto *mod = modules.find(ctx.Eip)) {
                frame.libName = mod->name;
                frame.libBase = mod->base;
                if (auto *exp = mod->find_export_le(ctx.Eip)) {
                    frame.symName = exp->name;
                    frame.symAddr = exp->addr;
                    printf("unwind lib %s:%s+%X\n", frame.libName.c_str(), frame.symName.c_str(), ctx.Eip - frame.symAddr);
                } else {
                    printf("unwind lib %s+%X\n", frame.libName.c_str(), ctx.Eip - frame.libBase);
                }
            } else {
                printf("unwind lib unk %p\n", ctx.Eip);
            }
            ctx.Eip = *bp++;
            ctx.Esp = (uint32_t) bp;
            printf("ctx.Esp=%p\n", ctx.Esp);
        }
    }

};

LPTOP_LEVEL_EXCEPTION_FILTER g_prev = nullptr;
LONG WINAPI TopLevelExceptionFilter(_In_ struct _EXCEPTION_POINTERS *ExceptionInfo) {
    controlOtherThreadsInCurProc(true);
    std::stringstream ss;
    ss << "caught exception " << fmtHex32(ExceptionInfo->ExceptionRecord->ExceptionCode) << " at " << fmtHex32(ExceptionInfo->ExceptionRecord->ExceptionAddress) << std::endl;
    ss << "tid: " << GetCurrentThreadId() << "(0x" << fmtHex(GetCurrentThreadId()) << ")" << std::endl;
    ss << "exe base: " << fmtHex32(bughunter::base) << std::endl;
    auto &R = *ExceptionInfo->ContextRecord;
    ss << "eax=" << fmtHex32(R.Eax) << " ebx=" << fmtHex32(R.Ebx) << " ecx=" << fmtHex32(R.Ecx) << " edx=" << fmtHex32(R.Edx) << std::endl;
    ss << "esi=" << fmtHex32(R.Esi) << " edi=" << fmtHex32(R.Edi) << " esp=" << fmtHex32(R.Esp) << " ebp=" << fmtHex32(R.Ebp) << std::endl;
    ss << "eip=" << fmtHex32(R.Eip) << " efl=" << fmtHex32(R.EFlags) << std::endl;

    LoadedModules modules;
    {
        StackWalker sw(modules, R);
        sw.test();
        sw.test();
        sw.test();
        sw.test();
        sw.test();
    }

    std::string text = ss.str();
    // hide game windows and show crash menu
    hideFullscreenWindow();
    MessageBoxA(NULL, text.c_str(), "Flame bug hunter", MB_OK | MB_ICONERROR | MB_DEFAULT_DESKTOP_ONLY | MB_TASKMODAL);
    controlOtherThreadsInCurProc(false);
    return g_prev(ExceptionInfo);
}

void bug_hunter::init() {
    resolveLocs();
    parseFpomap();
    g_prev = SetUnhandledExceptionFilter(TopLevelExceptionFilter);
}
