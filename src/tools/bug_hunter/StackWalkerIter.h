//
// Created by DiaLight on 9/17/2025.
//

#ifndef FLAME_STACKWALKERITER_H
#define FLAME_STACKWALKERITER_H

struct StackFrame;
struct StackWalkerState;

class StackWalkerEnd {};
class StackWalkerIter {

    StackWalkerState &state;
public:
    explicit StackWalkerIter(StackWalkerState &state);

    StackFrame &operator*() const noexcept;
    StackFrame *operator->() const noexcept;

    bool operator!=(const StackWalkerEnd &) const noexcept;

    StackWalkerIter &operator++() noexcept;

};


#endif // FLAME_STACKWALKERITER_H
