//
// Created by DiaLight on 23.06.2024.
//
#include "Struct.h"
#include "ScopeLineIter.h"
#include "Type.h"

bool Field::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] Field::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "type") {
            type = parseType(sli, shortProps2, arena);
            if(!type) {
                printf("[-] Field::deserialize parse type failed \"%s\" at %d\n", key.c_str(), sli.it.line_num);
                return false;
            }
        } else {
            printf("[-] Field::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}


bool Struct::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    id = shortProps["id"];
    path = getStrOptional(shortProps, "path", "");
    if(!parseInt(shortProps["size"], size)) {
        printf("[-] Struct::deserialize struct has no size at %d\n", sli.it.line_num);
        return false;
    }
    is_union = getBoolOptional(shortProps, "is_union", false);
    _vtable_id = getStrOptional(shortProps, "vtable", "");
    _super_id = getStrOptional(shortProps, "super", "");
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] Struct::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "field") {
            auto &field = fields.emplace_back(shortProps2["name"]);
            {
                ScopeLineIter sub_sli(sli.it, sli.level + 1);
                if(!field.deserialize(sub_sli, shortProps, arena)) {
                    printf("[-] Struct::deserialize failed parse field at %d\n", sli.it.line_num);
                    return false;
                }
            }
        } else if(key == "vtable_value") {
            uint32_t va;
            if(!parseHexInt32(shortProps2["va"], va)) {
                printf("[-] Struct::deserialize failed parse va at %d\n", sli.it.line_num);
                return false;
            }
            vtable_values.push_back(va);
        } else {
            printf("[-] Struct::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}

size_t Struct::calcFieldOffs() const {
    size_t offs = 0;
    if(vtable) offs += 4;
    if(super) {
        if(super->vtable) {
            offs += super->size - 4;
        } else {
            offs += super->size;
        }
    }
    return offs;
}

size_t Struct::calcFieldsSize() {
    size_t size = 0;
    for(auto &field : fields) {
        size += field.type->calcSize();
    }
    return size;
}

bool Struct::link(std::map<std::string, Struct *> &structsMap) {
    if(_linked) return true;
    if(!_vtable_id.empty()) {
        if(!getStruct(structsMap, _vtable_id, vtable)) return false;
    }
    if(!_super_id.empty()) {
        if(!getStruct(structsMap, _super_id, super)) return false;
    }
    for(auto &field : fields) {
        if(!field.type->link(structsMap)) return false;
    }
    _linked = true;
    return true;
}

