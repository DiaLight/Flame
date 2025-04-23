//
// Created by DiaLight on 13.09.2024.
//

#ifndef FLAME_BUG_HUNTER_H
#define FLAME_BUG_HUNTER_H

#include <Windows.h>
#include <memory>
#include "LoadedModules.h"
#include "StackLimits.h"

namespace bug_hunter {
    extern bool stopped;
    void init();
    void keyWatcher();
}

class WalkerError {
    std::string error;
public:
    WalkerError() = default;

    inline bool operator ! () const { return error.empty(); }
    inline explicit operator bool() const { return !error.empty(); }

    std::string str() { return error; }
    const char *c_str() { return error.c_str(); }

private:
    friend struct StackWalkerState;
    void set(const char *err) { this->error = err; }
    void set(const std::string &err) { this->error = err; }

};

struct StackFrame {

    DWORD eip = 0;
    DWORD esp = 0;
    DWORD ebp = 0;

    std::string libName;
    DWORD libBase = 0;
    std::string symName;
    DWORD symAddr = 0;

    friend std::ostream &operator<<(std::ostream &os, const StackFrame &frame);

};

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

void dumpCurrentStack(int numFrames=-1);
void traceCurrentStack(std::vector<StackFrame> &frames, WalkerError &err);


#endif //FLAME_BUG_HUNTER_H
