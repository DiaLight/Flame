//
// Created by DiaLight on 9/17/2025.
//

#include "StackWalker.h"
#include "StackWalkerState.h"


StackWalker::StackWalker(LoadedModules &modules, StackLimits &limits, CONTEXT &ctx, WalkerError &err)
    : state(std::make_unique<StackWalkerState>(modules, limits, ctx, err)) {}


