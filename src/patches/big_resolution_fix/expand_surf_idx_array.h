//
// Created by DiaLight on 9/28/2025.
//

#ifndef FLAME_EXPAND_SURF_IDX_ARRAY_H
#define FLAME_EXPAND_SURF_IDX_ARRAY_H


#include "dk2/RtGuiView.h"

namespace patch::expand_surf_idx_array {

    extern bool enabled;

    void allocate(dk2::RtGuiView *self);
    int *getPIdx(dk2::RtGuiView *self, int x, int y);

}


#endif // FLAME_EXPAND_SURF_IDX_ARRAY_H
