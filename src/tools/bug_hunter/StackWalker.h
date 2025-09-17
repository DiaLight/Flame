//
// Created by DiaLight on 9/17/2025.
//

#ifndef FLAME_STACKWALKER_H
#define FLAME_STACKWALKER_H

#include <Windows.h>
#include <memory>
#include "StackWalkerIter.h"

struct StackLimits;
class WalkerError;
class LoadedModules;
class StackWalkerState;
class StackWalker {

    std::unique_ptr<StackWalkerState> state;
public:
    explicit StackWalker(LoadedModules &modules, StackLimits &limits, CONTEXT &ctx, WalkerError &err);

    StackWalker(const StackWalker& R) noexcept = delete;
    StackWalker& operator=(const StackWalker& R) noexcept = delete;

    StackWalkerIter begin() { return StackWalkerIter(*state); }
    static StackWalkerEnd end() { return {}; }

};


#endif // FLAME_STACKWALKER_H
