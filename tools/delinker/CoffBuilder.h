//
// Created by DiaLight on 18.06.2024.
//

#ifndef FLAME_COFFBUILDER_H
#define FLAME_COFFBUILDER_H

#include <vector>
#include "chunk/Chunk.h"

[[nodiscard]] bool buildCoff(std::vector<Chunk *> &chunks, std::vector<uint8_t> &buf);


#endif //FLAME_COFFBUILDER_H
