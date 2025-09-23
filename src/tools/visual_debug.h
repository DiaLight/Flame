//
// Created by DiaLight on 3/27/2025.
//

#ifndef VISUAL_DEBUG_H
#define VISUAL_DEBUG_H

#include <dk2/MyDdSurface.h>
#include <dk2/MySurface.h>
#include "dk2/CEngineSurface.h"
#include <vector>

void println(dk2::MySurface &surf);
void println(DDSURFACEDESC &desc);
void println(dk2::AABB aabb);
void println(dk2::MyDdSurface &surf);
void println(dk2::MyDdSurfaceEx &ddSurface);

void dump(dk2::MySurface &surf, int timeout = -1);
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, int timeout = -1);
void dump(dk2::MySurface &surf1, dk2::MySurface &surf2, dk2::MySurface &surf3, int timeout = -1);
void dump(std::vector<dk2::MySurface *> surfaces, int timeout = -1);

void dump(dk2::CEngineSurface &surf, int timeout = -1);
void dump(std::vector<dk2::CEngineSurface *> &surfs, int timeout = -1);
void dump(int timeout = -1);

#endif //VISUAL_DEBUG_H
