//
// Created by DiaLight on 9/28/2025.
//

#include "expand_surf_idx_array.h"
#include "patches/logging.h"


// malloc array instead use builtin limited to 140 dwords
bool patch::expand_surf_idx_array::enabled = true;

void patch::expand_surf_idx_array::allocate(dk2::RtGuiView *self) {
    DWORD *&arr = *(DWORD **) &self->Arrp31x400_ids[0];
    if (arr == nullptr) {
        arr = (DWORD *) malloc(8192 * sizeof(DWORD));  // 5760 needs for 8K resolution
        ZeroMemory(arr, 8192 * sizeof(DWORD));
//        patch::log::dbg("%p create array %p instead builtin limited to 140 dwords", self, arr);
    } else {
        patch::log::err("%p array already created %p", self, arr);
    }
}
int *patch::expand_surf_idx_array::getPIdx(dk2::RtGuiView *self, int x, int y) {
    int *newArrp31x400_ids = (int *) self->Arrp31x400_ids[0];
    return &newArrp31x400_ids[x + self->width_128blocks * y];
}

