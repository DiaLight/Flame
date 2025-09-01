//
// Created by DiaLight on 8/12/2025.
//

#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <functional>

namespace patch::scheduler {

    void tick();
    void schedule(std::function<void()> &&func, size_t ms);

};



#endif //SCHEDULER_H
