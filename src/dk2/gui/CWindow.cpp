//
// Created by DiaLight on 7/12/2026.
//
#include "dk2/gui/CWindow.h"
#include "dk2/utils/AABB.h"
#include "dk2/gui/CGuiManager.h"

dk2::AABB *dk2::CWindow::getScreenPos(AABB *a2) {
    int parent_x;
    int parent_y;
    if (CWindow *parent = this->f52_parent) {
        AABB tmp;
        AABB *pos = parent->getScreenPos(&tmp);
        parent_x = pos->minX;
        parent_y = pos->minY;
    } else {
        parent_x = this->f4A_c_gui_manager->aabb.minX;
        parent_y = this->f4A_c_gui_manager->aabb.minY;
    }
    int x = parent_x + this->pos.x;
    int y = parent_y + this->pos.y;

    *a2 = AABB {x, y, x + this->pos.w, y + this->pos.h};
    return a2;
}
