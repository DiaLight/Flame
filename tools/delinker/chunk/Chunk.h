//
// Created by DiaLight on 15.06.2024.
//

#ifndef FLAME_CHUNK_H
#define FLAME_CHUNK_H

#include <vector>
#include <map>
#include "ChunkRef.h"
#include "ChunkArena.h"

std::string format_acc(uint32_t chars);

struct Chunk {

    uint32_t va = 0;
    std::string name;
    std::string exeSecName;
    std::string objSecName;
    std::string objName;
    std::vector<uint8_t> data;
    std::vector<ChunkRef *> refs;
    std::vector<ChunkRef *> xrefs;
    uint32_t chars = 0;
    // do not copy at split
    bool isJumpTable = false;
    bool isExcluded = false;
    // fill after all splits
    std::map<uint32_t, std::string> symbols;

    // constructor
    Chunk() = default;
    // Copy constructor
    Chunk(const Chunk & other) = delete;
    // Move constructor
    Chunk(Chunk && other) = delete;
    // Copy assignment
    Chunk & operator=(const Chunk & other) = delete;
    // Move assignment operator
    Chunk & operator=(Chunk && other) = delete;

    [[nodiscard]] std::string acc() const { return format_acc(chars); }

    bool isUninitialized() const;

    bool isReadonly() const;
    bool isReadWrite() const;
    bool isExecute() const;

    Chunk *split(int offs, ChunkArena &arena);

};


#endif //FLAME_CHUNK_H
