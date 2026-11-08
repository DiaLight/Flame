//
// Created by DiaLight on 6/1/2026.
//

#ifndef FLAME_PNG_SUPPORT_H
#define FLAME_PNG_SUPPORT_H


#include "dk2/CEngineSurfaceBase.h"

namespace png_support {

    bool save(dk2::CEngineSurfaceBase &surf, const char *pngFile);
    bool save_bgra32(void *data, size_t width, size_t height, size_t pitch, const char *pngFile);

    dk2::CEngineSurface *load(const char *pngFile);
//    bool loadTo(dk2::CEngineSurfaceBase &surf, const char *pngFile, int x = 0, int y = 0);

}


#endif //FLAME_PNG_SUPPORT_H
