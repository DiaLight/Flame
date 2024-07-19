//
// Created by DiaLight on 23.06.2024.
//

#ifndef FLAME_TYPE_H
#define FLAME_TYPE_H

#include <map>
#include <string>
#include <memory>
#include <vector>

struct Struct;
struct ScopeLineIter;
struct SGMapArena;

enum TypeKind {
    TK_Void,
    TK_Ptr,
    TK_Int,
    TK_Float,
    TK_Struct,
    TK_Function,
    TK_Array,
    TK_Winapi,
};

bool getStruct(std::map<std::string, Struct *> &structsMap, const std::string &id, Struct *&struc);

struct Type {
    TypeKind kind;
    explicit Type(TypeKind kind) : kind(kind) {}
    virtual ~Type() = default;

    [[nodiscard]] virtual bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &sprops, SGMapArena &arena) = 0;
    [[nodiscard]] virtual size_t calcSize() = 0;
    [[nodiscard]] virtual bool link(std::map<std::string, Struct *> &structsMap) { return true; }

    bool operator <(const Type& rhs) const {
        if(kind != rhs.kind) return kind < rhs.kind;
        return lt(&rhs);
    }

private:
    virtual bool lt(const Type *rhs) const = 0;

};

static_assert(sizeof(Type) == 8);


struct VoidType : public Type {

    VoidType() : Type(TK_Void) {}
    ~VoidType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;

private:
    bool lt(const Type *rhs) const override;

};


struct PtrType : public Type {

    Type *type;
    bool is_const;
    std::string winapi;

    explicit PtrType(Type *type, bool is_const=false) : Type(TK_Ptr),
                                                                        type(type), is_const(is_const) {}
    ~PtrType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;
    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap) override;

private:
    bool lt(const Type *rhs) const override;

};


struct IntType : public Type {

    size_t size;
    bool is_signed;
    std::string winapi;
    std::string fname;

    explicit IntType(size_t size, bool is_signed=false) : Type(TK_Int), size(size), is_signed(is_signed) {}
    ~IntType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;

private:
    bool lt(const Type *rhs) const override;

};


struct FloatType : public Type {

    size_t size{};

    explicit FloatType(size_t size) : Type(TK_Float), size(size) {}
    ~FloatType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;

private:
    bool lt(const Type *rhs) const override;

};


struct StructType : public Type {

    Struct *struc;
    std::string _struct_id;

    explicit StructType(Struct *struc) : Type(TK_Struct), struc(struc) {}
    ~StructType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;
    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap) override;

private:
    bool lt(const Type *rhs) const override;

};

enum CConv {
    DS_stdcall,
    DS_cdecl,
    DS_cdecl_varargs,
    DS_fastcall,
    DS_thiscall,
    DS_assembly,
};

[[nodiscard]] bool parseDeclspec(const std::string& name, CConv &val);


struct FunctionType : public Type {

    CConv cconv;
    std::vector<Type *> args;
    Type *ret;

    FunctionType(CConv declspec, Type *ret) : Type(TK_Function), cconv(declspec), ret(std::move(ret)) {}
    ~FunctionType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;
    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap) override;

private:
    bool lt(const Type *rhs) const override;

};


struct ArrayType : public Type {

    Type *type;
    size_t count;

    ArrayType(Type *type, size_t count) : Type(TK_Array), type(type), count(count) {}
    ~ArrayType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;
    [[nodiscard]] bool link(std::map<std::string, Struct *> &structsMap) override;

private:
    bool lt(const Type *rhs) const override;

};


struct WinapiType : public Type {

    std::string name;
    size_t size;

    WinapiType(std::string name, size_t size) : Type(TK_Winapi), name(std::move(name)), size(size) {}
    ~WinapiType() override = default;

    [[nodiscard]] static Type *create(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);
    [[nodiscard]] bool deserialize(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena) override;
    [[nodiscard]] size_t calcSize() override;

private:
    bool lt(const Type *rhs) const override;

};


[[nodiscard]] Type *parseType(ScopeLineIter &sli, std::map<std::string, std::string> &shortProps, SGMapArena &arena);


#endif //FLAME_TYPE_H
