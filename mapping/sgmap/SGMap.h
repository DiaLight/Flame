//
// Created by DiaLight on 20.06.2024.
//

#ifndef FLAME_SGMAP_H
#define FLAME_SGMAP_H

#include <string>
#include <vector>
#include <memory>
#include "Struct.h"
#include "Global.h"
#include "Type.h"

struct SGMapArena {

    std::vector<std::unique_ptr<Struct>> structs;
    std::vector<std::unique_ptr<Global>> globals;
    std::vector<std::unique_ptr<Type>> types;

};

[[nodiscard]] bool SGMap_deserialize(
        std::istream &is,
        std::vector<Struct *> &structs,
        std::vector<Global *> &globals,
        SGMapArena &arena
);
[[nodiscard]] bool SGMap_link(
        std::vector<Struct *> &structs,
        std::vector<Global *> &globals
);


#endif //FLAME_SGMAP_H
