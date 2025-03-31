//
// Created by DiaLight on 3/27/2025.
//

#ifndef VISUAL_DEBUG_H
#define VISUAL_DEBUG_H

#include <vector>
#include <dk2/MyDdSurface.h>
#include <dk2/MySurface.h>

void println(dk2::MySurface &surf);
void println(DDSURFACEDESC &desc);
void println(dk2::AABB aabb);
void println(dk2::MyDdSurface &surf);
void println(dk2::MyDdSurfaceEx &ddSurface);

void dump(dk2::MySurface &surf);
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2);
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, dk2::MySurface &surf3);
void dump(std::vector<dk2::MySurface *> surfaces);

#endif //VISUAL_DEBUG_H
