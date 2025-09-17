//
// Created by DiaLight on 9/17/2025.
//

#ifndef FLAME_STACKWALKERSTATE_H
#define FLAME_STACKWALKERSTATE_H

#include <Windows.h>
#include <string>
#include "StackFrame.h"
#include "WalkerError.h"

class LoadedModules;
struct StackLimits;

struct StackWalkerState {
    LoadedModules &modules;
    StackLimits &limits;
    CONTEXT& ctx;
    WalkerError &err;
    StackFrame frame;
    bool isEbpValid = false;

    ULONG_PTR BaseThreadInitThunk = 0;

    explicit StackWalkerState(LoadedModules &modules, StackLimits &limits, CONTEXT &ctx, WalkerError &err);

    bool isAnyCode(DWORD eip);

    [[nodiscard]] bool stackEndCondition() const;
    void tryStep();
    void step();

    static void setError(WalkerError &err, const std::string &str) {
        err.set(str);
    }

};


#endif // FLAME_STACKWALKERSTATE_H
