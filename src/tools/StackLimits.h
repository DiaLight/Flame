//
// Created by DiaLight on 09.09.2023.
//

#ifndef EMBER_STACKLIMITS_H
#define EMBER_STACKLIMITS_H

#include <Windows.h>

struct StackLimits {
    ULONG_PTR low;
    ULONG_PTR high;

    StackLimits();

    void resolve();
    bool resolve(HANDLE hThread);

    bool contains(ULONG_PTR addr);

};

#endif //EMBER_STACKLIMITS_H
