//
// Created by DiaLight on 3/27/2025.
//

#ifndef VISUAL_DEBUG_H
#define VISUAL_DEBUG_H

#include <dk2/MyDdSurface.h>
#include <dk2/MySurface.h>

void println(dk2::MySurface &surf);
void println(DDSURFACEDESC &desc);
void println(dk2::AABB aabb);
void println(dk2::MyDdSurface &surf);
void println(dk2::MyDdSurfaceEx &ddSurface);

void dump(dk2::MySurface &surf);

#endif //VISUAL_DEBUG_H
