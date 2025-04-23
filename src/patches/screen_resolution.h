//
// Created by DiaLight on 4/6/2025.
//

#ifndef SCREEN_RESOLUTION_H
#define SCREEN_RESOLUTION_H

#include <cstdint>

namespace patch::screen_resolution {

    extern bool enabled;
    void init();

    void patchMenuWindowResolution(uint32_t &width, uint32_t &height);
    void patchGameWindowResolution();

}

#include <Windows.h>

#endif //SCREEN_RESOLUTION_H
