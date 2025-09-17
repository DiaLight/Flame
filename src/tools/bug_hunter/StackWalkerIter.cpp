//
// Created by DiaLight on 9/17/2025.
//

#include "StackWalkerIter.h"
#include "StackWalkerState.h"


StackWalkerIter::StackWalkerIter(StackWalkerState &state) : state(state) {
    state.step();
}

StackFrame &StackWalkerIter::operator*() const noexcept { return state.frame; }

StackFrame *StackWalkerIter::operator->() const noexcept { return &state.frame; }

bool StackWalkerIter::operator!=(const StackWalkerEnd &) const noexcept {
    if(state.frame.esp == 0) return false;
    if(state.err) return false;
    return true;
}

StackWalkerIter &StackWalkerIter::operator++() noexcept {
    state.step();
    return *this;
}
