//
// Created by DiaLight on 13.09.2024.
//

#ifndef FLAME_BUG_HUNTER_H
#define FLAME_BUG_HUNTER_H

#include <Windows.h>
#include <memory>
#include "LoadedModules.h"
#include "StackLimits.h"
#include "tools/bug_hunter/MyFpoFun.h"
#include "tools/bug_hunter/StackFrame.h"
#include "tools/bug_hunter/WalkerError.h"

namespace bug_hunter {
    extern bool stopped;
    void init();
    void displayCrash();
    void collectStackInfo();
    void keyWatcher();
}

namespace bughunter {
    extern std::shared_ptr<LoadedModule> weanetr;
    extern std::shared_ptr<LoadedModule> qmixer;

    std::vector<MyFpoFun>::iterator find_gt(std::vector<MyFpoFun> &fpos, DWORD rva);
    std::vector<MyFpoFun>::iterator find_le(std::vector<MyFpoFun> &fpos, DWORD rva);

    extern uintptr_t dkii_base;
    extern uintptr_t dkii_entry;
    extern uintptr_t dkii_fpomap_start;
    extern uintptr_t dkii_text_start;
    extern uintptr_t dkii_text_end;
    extern std::vector<MyFpoFun> dkii_fpomap;

    bool isDkiiCode(DWORD ptr) noexcept;

    extern uintptr_t flame_base;
    extern uintptr_t flame_fpomap_start;
    extern uintptr_t flame_text_start;
    extern uintptr_t flame_text_end;
    extern std::vector<MyFpoFun> flame_fpomap;

    bool isFlameCode(DWORD ptr) noexcept;
}


void dumpCurrentStack(int numFrames=-1);
void traceCurrentStack(std::vector<StackFrame> &frames, WalkerError &err);


#endif //FLAME_BUG_HUNTER_H
