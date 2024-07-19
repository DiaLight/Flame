//
// Created by DiaLight on 15.06.2024.
//

#ifndef FLAME_CHUNKREF_H
#define FLAME_CHUNKREF_H


#include <cstdint>
#include <iostream>
#include <utility>
#include <vector>
#include <Windows.h>


struct Chunk;

struct ChunkReloc {
    enum RelocType {
        RT_VA32,
        RT_REL32,
    };

    uint32_t offs = 0;
    uint32_t value = 0;
    uint16_t type = IMAGE_REL_I386_DIR32;
    uint32_t offsTo = 0;


    ChunkReloc() = default;
    ChunkReloc(uint32_t offs, uint16_t type, uint32_t offsTo) : offs(offs), type(type), offsTo(offsTo) {}
};

struct ChunkRef {
    ChunkReloc rel;
    Chunk *chunk;

    // constructor
    ChunkRef() = default;
    ChunkRef(ChunkReloc rel, Chunk *chunk) : rel(rel), chunk(chunk) {}
    // Copy constructor
    ChunkRef(const ChunkRef & other) = delete;
    // Move constructor
    ChunkRef(ChunkRef && other) = delete;
    // Copy assignment
    ChunkRef & operator=(const ChunkRef & other) = delete;
    // Move assignment operator
    ChunkRef & operator=(ChunkRef && other) = delete;
};


#endif //FLAME_RELOC_H
