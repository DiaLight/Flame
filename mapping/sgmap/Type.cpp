//
// Created by DiaLight on 23.06.2024.
//
#include "Type.h"
#include "Struct.h"
#include "ScopeLineIter.h"
#include "SGMap.h"

bool getStruct(std::map<std::string, Struct *> &structsMap, const std::string &id, Struct *&struc) {
    auto it = structsMap.find(id);
    if(it == structsMap.end()) {
        printf("[-] struct %s not found\n", id.c_str());
        return false;
    }
    struc = it->second;
    return true;
}

Type *VoidType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new VoidType()).get();
}

bool VoidType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return true;
}

size_t VoidType::calcSize() {
    throw std::exception("void does not have size");
    return 0;
}

bool VoidType::lt(const Type *rhs) const {
    return false;
}


Type *PtrType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new PtrType(nullptr)).get();
}

bool PtrType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    is_const = getBoolOptional(shortProps, "is_const", false);
    winapi = getStrOptional(shortProps, "winapi", "");
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] PtrType::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "type") {
            this->type = parseType(sli, shortProps2, arena);
            if(!this->type) {
                printf("[-] PtrType::deserialize parse subtype failed \"%s\" at %d\n", key.c_str(), sli.it.line_num);
                return false;
            }
        } else {
            printf("[-] PtrType::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}

size_t PtrType::calcSize() {
    return 4;
}

bool PtrType::link(std::map<std::string, Struct *> &structsMap) {
    return type->link(structsMap);
}

bool PtrType::lt(const Type *rhs) const {
    const PtrType *rhsty = (PtrType *) rhs;
    if(is_const != rhsty->is_const) return is_const < rhsty->is_const;
    if(winapi < rhsty->winapi) return true;
    if(rhsty->winapi < winapi) return false;
    return *type < *rhsty->type;
}


Type *IntType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new IntType(0)).get();
}

bool IntType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    if(!parseInt(shortProps["size"], size)) return true;
    is_signed = getBoolOptional(shortProps, "signed", false);
    winapi = getStrOptional(shortProps, "winapi", "");
    fname = getStrOptional(shortProps, "fname", "");
    return true;
}

size_t IntType::calcSize() {
    return size;
}

bool IntType::lt(const Type *rhs) const {
    const IntType *rhsty = (IntType *) rhs;
    if(size != rhsty->size) return size < rhsty->size;
    if(is_signed != rhsty->is_signed) return is_signed < rhsty->is_signed;
    return winapi < rhsty->winapi;
}


Type *FloatType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new FloatType(0)).get();
}

bool FloatType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    if(!parseInt(shortProps["size"], size)) return true;
    return true;
}

size_t FloatType::calcSize() {
    return size;
}

bool FloatType::lt(const Type *rhs) const {
    const FloatType *rhsty = (FloatType *) rhs;
    return size < rhsty->size;
}


Type *StructType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new StructType(nullptr)).get();
}

bool StructType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    _struct_id = shortProps["id"];
    return true;
}

size_t StructType::calcSize() {
    if(struc->size == 0) {
        struc->size = struc->calcFieldsSize();
    }
    return struc->size;
}

bool StructType::link(std::map<std::string, Struct *> &structsMap) {
    if(!getStruct(structsMap, _struct_id, struc)) return false;
    return true;
}

bool StructType::lt(const Type *rhs) const {
    const StructType *rhsty = (StructType *) rhs;
    return _struct_id < rhsty->_struct_id;
}

bool parseDeclspec(const std::string& name, CConv &val) {
    if(name == "stdcall") {
        val = DS_stdcall;
    } else if(name == "cdecl") {
        val = DS_cdecl;
    } else if(name == "cdecl_varargs") {
        val = DS_cdecl_varargs;
    } else if(name == "fastcall") {
        val = DS_fastcall;
    } else if(name == "thiscall") {
        val = DS_thiscall;
    } else if(name == "assembly") {
        val = DS_assembly;
    } else {
        return false;
    }
    return true;
}


Type *FunctionType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new FunctionType(DS_stdcall, nullptr)).get();
}

bool FunctionType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    if(!parseDeclspec(shortProps["declspec"], cconv)) return false;
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] FunctionType::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "ret") {
            this->ret = parseType(sli, shortProps2, arena);
            if(!this->ret) return false;
        } else if(key == "arg") {
            auto arg = parseType(sli, shortProps2, arena);
            if(!arg) return false;
            args.push_back(arg);
        } else {
            printf("[-] FunctionType::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}

size_t FunctionType::calcSize() {
    throw std::exception("unimplemented");
    return 0;
}

bool FunctionType::link(std::map<std::string, Struct *> &structsMap) {
    for(auto &arg : args) if(!arg->link(structsMap)) return false;
    return ret->link(structsMap);
}

bool FunctionType::lt(const Type *rhs) const {
    const FunctionType *rhsty = (FunctionType *) rhs;
    if(cconv != rhsty->cconv) return cconv < rhsty->cconv;
    if(args.size() != rhsty->args.size()) return args.size() < rhsty->args.size();
    for (int i = 0; i < args.size(); ++i) {
        if(args[i] < rhsty->args[i]) return true;
        if(rhsty->args[i] < args[i]) return false;
    }
    return *ret < *rhsty->ret;
}


Type *ArrayType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new ArrayType(nullptr, 0)).get();
}

bool ArrayType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    if(!parseInt(shortProps["count"], count)) return true;
    while (true) {
        std::string *line = sli.next();
        if(line == nullptr) break;
        std::string key;
        std::map<std::string, std::string> shortProps2;
        if(!_parseShort(*line, key, shortProps2)) {
            printf("[-] ArrayType::deserialize invalid \"%s\" at %d\n", line->c_str(), sli.it.line_num);
            return false;
        }
        if(key == "type") {
            this->type = parseType(sli, shortProps2, arena);
            if(!this->type) return false;
        } else {
            printf("[-] ArrayType::deserialize invalid \"%s\" at %d\n", key.c_str(), sli.it.line_num);
            return false;
        }
    }
    return true;
}

size_t ArrayType::calcSize() {
    return type->calcSize() * count;
}

bool ArrayType::link(std::map<std::string, Struct *> &structsMap) {
    return type->link(structsMap);
}

bool ArrayType::lt(const Type *rhs) const {
    const ArrayType *rhsty = (ArrayType *) rhs;
    if(count != rhsty->count) return count < rhsty->count;
    return *type < *rhsty->type;
}


Type *WinapiType::create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    return arena.types.emplace_back(new WinapiType("", 0, false)).get();
}

bool WinapiType::deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    name = shortProps["name"];
    size = getIntOptional(shortProps, "size", 0);
    is_union = getBoolOptional(shortProps, "is_union", false);
    return true;
}

size_t WinapiType::calcSize() {
    return size;
}

bool WinapiType::lt(const Type *rhs) const {
    const WinapiType *rhsty = (WinapiType *) rhs;
    if(size != rhsty->size) return size < rhsty->size;
    if(is_union != rhsty->is_union) return is_union < rhsty->is_union;
    return name < rhsty->name;
}


Type *parseType(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) {
    Type *type;
    std::string kind = shortProps["kind"];
    if(kind == "void") {
        type = VoidType::create(sli, shortProps, arena);
    } else if(kind == "ptr") {
        type = PtrType::create(sli, shortProps, arena);
    } else if(kind == "int") {
        type = IntType::create(sli, shortProps, arena);
    } else if(kind == "float") {
        type = FloatType::create(sli, shortProps, arena);
    } else if(kind == "struct") {
        type = StructType::create(sli, shortProps, arena);
    } else if(kind == "function") {
        type = FunctionType::create(sli, shortProps, arena);
    } else if(kind == "array") {
        type = ArrayType::create(sli, shortProps, arena);
    } else if(kind == "winapi") {
        type = WinapiType::create(sli, shortProps, arena);
    } else {
        printf("[-] unknown type %s at %d\n", kind.c_str(), sli.it.line_num);
        return {};
    }
    {
        ScopeLineIter subSli(sli.it, sli.level + 1);
        if(!type->deserialize(subSli, shortProps, arena)) {
            printf("[-] failed deserialize type %s at %d\n", kind.c_str(), sli.it.line_num);
            return {};
        }
    }
    return type;
}

