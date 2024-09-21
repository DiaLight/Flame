//
// Created by DiaLight on 20.06.2024.
//

#include "SGMap.h"
#include "LineIter.h"
#include "ScopeLineIter.h"
#include <map>

bool SGMap_deserialize(
        std::istream &is,
        std::vector<Struct *> &structs,
        std::vector<Global *> &globals,
        SGMapArena &arena
) {
    LineIter it(is);
    ScopeLineIter sli(it);
    while(true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        if(line->empty()) continue;
        if((*line)[0] == '#') continue;
        std::string key;
        std::map<std::string, std::string> shortProps;
        if(!_parseShort(*line, key, shortProps)) {
            printf("[-] SGMap_deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "struct") {
            auto *struc = arena.structs.emplace_back(new Struct(shortProps["name"])).get();
            {
                ScopeLineIter sub_sli(sli.it, sli.level + 1);
                if(!struc->deserialize(sub_sli, shortProps, arena)) return false;
            }
            structs.push_back(struc);
        } else if(key == "global") {
            uint32_t va;
            if(!parseHexInt32(shortProps["va"], va)) return false;
            auto *glob = arena.globals.emplace_back(new Global(va, shortProps["name"])).get();
            {
                ScopeLineIter sub_sli(sli.it, sli.level + 1);
                if(!glob->deserialize(sub_sli, shortProps, arena)) return false;
            }
            globals.push_back(glob);
        } else {
            printf("[-] SGMap_deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return it.is.eof();
}

bool SGMap_link(
        std::vector<Struct *> &structs,
        std::vector<Global *> &globals
) {
    std::map<std::string, Struct *> structsMap;
    for (auto &struc : structs) {
        structsMap.insert(std::make_pair(struc->id, struc));
    }
    for (auto *struc : structs) if(!struc->link(structsMap)) return false;
    for (auto *glob : globals) if(!glob->link(structsMap)) return false;
    return true;
}

