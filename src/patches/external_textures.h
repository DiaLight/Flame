//
// Created by DiaLight on 10/8/2025.
//

#ifndef FLAME_EXTERNAL_TEXTURES_H
#define FLAME_EXTERNAL_TEXTURES_H


#include "dk2/CEngineSurfaceBase.h"

namespace patch::external_textures {

    void dumpTextures();
    dk2::CEngineSurfaceBase * loadFlameTexture(char *texName);

}


#endif // FLAME_EXTERNAL_TEXTURES_H
