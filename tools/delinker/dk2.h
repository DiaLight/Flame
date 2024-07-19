//
// Created by DiaLight on 16.06.2024.
//

#ifndef FLAME_DK2_H
#define FLAME_DK2_H

#include <vector>
#include "chunk/ChunkRef.h"
#include "chunk/ChunkArena.h"
#include "Global.h"
#include "VaReloc.h"

struct SectionChunk {
    uint32_t start;
    uint32_t end;
    std::string secName;
    std::vector<uint8_t> data;
    uint32_t chars = 0;
};

bool collectSectionChunks(uint8_t *base, std::vector<SectionChunk> &out);

bool buildChunks(std::vector<SectionChunk> &&sections, std::vector<VaReloc> &&relocs,
                 std::vector<Chunk *> &out,
                 ChunkArena &arena);
bool collectImports(uint8_t *base, std::vector<Global *> &out, SGMapArena &arena);


#endif //FLAME_DK2_H
