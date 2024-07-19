//
// Created by DiaLight on 23.06.2024.
//

#ifndef FLAME_GLOBAL_H
#define FLAME_GLOBAL_H

#include "ScopeLineIter.h"
#include "Type.h"
#include <map>
#include <utility>


struct Struct;
struct SGMapArena;

struct Global {

    uint32_t va;
    size_t size = 0;
    std::string name;
    std::string _member_of;
    Struct *member_of = nullptr;
    Type *type = nullptr;

    Global(uint32_t va, std::string name) : va(va), name(std::move(name)) {}

    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap);

};

std::vector<Global *>::iterator find_gt(std::vector<Global *> &relocs, uint32_t offs);
std::vector<Global *>::iterator find_ge(std::vector<Global *> &relocs, uint32_t offs);
std::vector<Global *>::iterator find_lt(std::vector<Global *> &relocs, uint32_t offs);
std::vector<Global *>::iterator find_le(std::vector<Global *> &relocs, uint32_t offs);


#endif //FLAME_GLOBAL_H
