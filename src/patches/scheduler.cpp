//
// Created by DiaLight on 8/12/2025.
//

#include "scheduler.h"

#include <Windows.h>

namespace {

    struct task_t {
        std::function<void()> func;
        DWORD start;
        size_t delta;

        bool tickRemove(DWORD time) {
            if ((time - start) <= delta) return false;
            func();
            return true;
        }
    };

    std::vector<task_t> g_tasks;
}

void patch::scheduler::tick() {
    DWORD time = GetTickCount();
    std::erase_if(g_tasks, [time](task_t& task) { return task.tickRemove(time); });
}

void patch::scheduler::schedule(std::function<void()> &&func, size_t ms) {
    g_tasks.emplace_back(func, GetTickCount(), ms);
}
