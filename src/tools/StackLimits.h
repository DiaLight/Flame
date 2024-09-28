//
// Created by DiaLight on 09.09.2023.
//

#ifndef EMBER_STACKLIMITS_H
#define EMBER_STACKLIMITS_H

#include <Windows.h>

struct StackLimits {
    ULONG_PTR low = 0;
    ULONG_PTR high = 0;

    StackLimits();

    void resolve();
    bool resolve(HANDLE hThread);

    bool contains(ULONG_PTR addr);

};

#endif //EMBER_STACKLIMITS_H
