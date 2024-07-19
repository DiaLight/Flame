//
// Created by DiaLight on 23.06.2024.
//
#include "Global.h"
#include "Struct.h"

#include <utility>

bool Global::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    _member_of = getStrOptional(shortProps, "member_of", "");
    size = getIntOptional(shortProps, "size", 0);
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] Global::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "type") {
            this->type = parseType(sli, shortProps2, arena);
            if(!this->type) return false;
        } else {
            printf("[-] Global::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}

bool Global::link(std::map<std::string, Struct *> &structsMap) {
    if(!type->link(structsMap)) return false;
    if(!_member_of.empty()) {
        member_of = structsMap[_member_of];
        if(!member_of) {
            printf("[-] struct %s for member %s not found\n", _member_of.c_str(), name.c_str());
            return false;
        }
    }
    if(size == 0) {
        size = type->calcSize();
    }
    return true;
}

std::vector<Global *>::iterator find_gt(std::vector<Global *> &relocs, uint32_t offs) {
    return std::upper_bound(relocs.begin(), relocs.end(), offs, [](uint32_t offs, Global *bl) {  // <
        return offs < bl->va;
    });
}

std::vector<Global *>::iterator find_ge(std::vector<Global *> &relocs, uint32_t offs) {
    return std::lower_bound(relocs.begin(), relocs.end(), offs, [](Global *bl, uint32_t offs) {  // <=
        return bl->va < offs;
    });
}

std::vector<Global *>::iterator find_lt(std::vector<Global *> &relocs, uint32_t offs) {
    auto it = find_ge(relocs, offs);
    if (it == relocs.begin()) return relocs.end();
    return it - 1;
}

std::vector<Global *>::iterator find_le(std::vector<Global *> &relocs, uint32_t offs) {
    auto it = find_gt(relocs, offs);
    if (it == relocs.begin()) return relocs.end();
    return it - 1;
}
