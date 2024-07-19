//
// Created by DiaLight on 23.06.2024.
//

#ifndef FLAME_STRUCT_H
#define FLAME_STRUCT_H

#include <map>
#include <utility>
#include <string>
#include <vector>
#include <memory>

struct Type;
struct Global;
struct ScopeLineIter;
struct SGMapArena;

struct Field {

    std::string name;
    Type *type = nullptr;

    explicit Field(std::string name) : name(std::move(name)) {}

    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);

};

struct Struct {

    std::string id;
    std::string path;
    std::string name;
    Struct *vtable = nullptr;
    std::vector<uint32_t> vtable_values;
    std::vector<Field> fields;
    std::vector<Global *> functions;
    size_t size = 0;
    Struct *super = nullptr;
    bool is_union = false;

    std::string _vtable_id;
    std::string _super_id;
    bool _linked = false;

    explicit Struct(std::string name) : name(std::move(name)) {}

    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);

    [[nodiscard]] size_t calcFieldOffs() const;
    [[nodiscard]] size_t calcFieldsSize();

    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap);

};

#endif //FLAME_STRUCT_H
