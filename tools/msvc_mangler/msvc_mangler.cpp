//
// Created by DiaLight on 02.07.2024.
//

#include <sstream>
#include <functional>
#include <ranges>
#include "msvc_mangler.h"
#include "Struct.h"




struct TypeRef {
    Type *ty;
    explicit TypeRef(Type *ty) : ty(ty) {}
    inline Type * operator ->() const { return ty; }
};
namespace std {
    template<> struct less<TypeRef> {
        bool operator() (const TypeRef& lhs, const TypeRef& rhs) const {
            return *lhs.ty < *rhs.ty;
        }
    };
}




// https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling


void mangleTagTypeKind(std::stringstream &ss, Type *ty) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l03100
//    switch (TTK) {
//        case TagTypeKind::Union:
//            Out << 'T';
//            break;
//        case TagTypeKind::Struct:
//        case TagTypeKind::Interface:
//            Out << 'U';
//            break;
//        case TagTypeKind::Class:
//            Out << 'V';  // there no classes in sgmap structures
//            break;
//        case TagTypeKind::Enum:
//            Out << "W4";  // there no enum in sgmap structures
//            break;
//    }
    if(ty->kind == TK_Struct) {
        auto *structTy = (StructType *) ty;
        if(structTy->struc->is_union) {
            ss << 'T';
        } else {
            ss << 'U';
        }
    }
    if(ty->kind == TK_Winapi) {
        auto *winTy = (WinapiType *) ty;
        if(winTy->is_union) {
            ss << 'T';
        } else {
            ss << 'U';
        }
    }
}

void mangleQualifiers(std::stringstream &ss, Type *ty, bool isMember) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l02137
    bool isVolatile = false;
    bool isConst = false;
    if(ty->kind == TK_Ptr) {
        auto *ptr = (PtrType *) ty;
        isConst = ptr->is_const;
    }
    if(!isMember) {
        if (isConst && isVolatile) {
            ss << 'D';
        } else if (isVolatile) {
            ss << 'C';
        } else if (isConst) {
            ss << 'B';
        } else {
            ss << 'A';
        }
    } else {
        if (isConst && isVolatile) {
            ss << 'T';
        } else if (isVolatile) {
            ss << 'S';
        } else if (isConst) {
            ss << 'R';
        } else {
            ss << 'Q';
        }
    }
}

//void manglePointerExtQualifiers(std::stringstream &ss, Type *ty) {
//    // Check if this is a default 64-bit pointer or has __ptr64 qualifier.
//    bool is64Bit = PointeeType.isNull() ? PointersAre64Bit :
//                   is64BitPointer(PointeeType.getQualifiers());
//    if (is64Bit && (PointeeType.isNull() || !PointeeType->isFunctionType()))
//        Out << 'E';
//
//    if (Quals.hasRestrict())
//        Out << 'I';
//
//    if (Quals.hasUnaligned() ||
//        (!PointeeType.isNull() && PointeeType.getLocalQualifiers().hasUnaligned()))
//        Out << 'F';
//}
void manglePointerCVQualifiers(std::stringstream &ss, Type *ty) {
    // <pointer-cv-qualifiers> ::= P  # no qualifiers
    //                         ::= Q  # const
    //                         ::= R  # volatile
    //                         ::= S  # const volatile
    bool isVolatile = false;
    bool isConst = false;
    if(ty->kind == TK_Ptr) {
        auto *ptr = (PtrType *) ty;
        isConst = ptr->is_const;
    }
    if (isConst && isVolatile) {
        ss << 'S';
    } else if (isVolatile) {
        ss << 'R';
    } else if (isConst) {
        ss << 'Q';
    } else {
        ss << 'P';
    }
}


void mangleName(std::stringstream &ss, const std::string &name, std::map<std::string, size_t> &backReference) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l00897
    auto it = backReference.find(name);
    if(it != backReference.end()) {
        ss << it->second;
    } else {
        ss << name;
        ss << "@";
        if(backReference.size() < 10) {
            backReference[name] = backReference.size();
        }
    }
}

void mangleCConv(std::stringstream &ss, CConv decl) {
    bool exported = true;
    switch (decl) {
        case DS_assembly:
        case DS_cdecl_varargs:
        case DS_cdecl: ss << (exported ? 'A' : 'B'); return;
        case DS_thiscall: ss << (exported ? 'E' : 'F'); return;
        case DS_stdcall: ss << (exported ? 'G' : 'H'); return;
        case DS_fastcall: ss << (exported ? 'I' : 'J'); return;
    }
}

void mangleFunction(std::stringstream &ss, Struct *member_of, FunctionType *fun, std::map<std::string, size_t> &backReference);
void mangleType(std::stringstream &ss, Type *ty, std::map<std::string, size_t> &backReference) {
    if(ty->kind == TK_Int) {
        auto *intTy = (IntType *) ty;
        if(intTy->size == 2 && !intTy->is_signed) {
            if(intTy->fname == "wchar_t") {
                ss << "_W";
                return;
            }
        }
        if(intTy->size == 1 && intTy->is_signed) {
            if(intTy->fname == "int8_t") {
                ss << "C";
                return;
            }
            if(intTy->winapi == "bool") {
                ss << "_N";
                return;
            }
        }
        // if 32 bit
        if(intTy->size == 4) {
            if(intTy->fname.starts_with("long") ||
                    intTy->fname.starts_with("LONG") ||
                    intTy->fname == "HRESULT") {
                ss << (intTy->is_signed ? 'J' : 'K');
                return;
            }
        }

        if(intTy->size == 1) { ss << (intTy->is_signed ? 'D' : 'E'); }
        else if(intTy->size == 2) { ss << (intTy->is_signed ? 'F' : 'G'); }
        else if(intTy->size == 4) { ss << (intTy->is_signed ? 'H' : 'I'); }
        else if(intTy->size == 8) { ss << (intTy->is_signed ? 'J' : 'K'); }
        else {
            printf("[-] unknown int size\n");
            throw std::exception();
        }
        return;
    }
    if(ty->kind == TK_Ptr) {  // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l03186
        auto *ptrTy = (PtrType *) ty;
        ss << 'P';
        // MicrosoftCXXNameMangler::mangleFunctionType
        if(ptrTy->type->kind == TK_Function) {
            auto *funTy = (FunctionType *) ptrTy->type;
            ss << '6';
            mangleCConv(ss, funTy->cconv);
            mangleType(ss, ptrTy->type, backReference);
        } else {
            mangleQualifiers(ss, ptrTy, false);
            mangleType(ss, ptrTy->type, backReference);
        }
        return;
    }
    if(ty->kind == TK_Float) {
        auto *fltTy = (FloatType *) ty;
        if(fltTy->size == 4) { ss << 'M'; }
        else if(fltTy->size == 8) { ss << 'N'; }
        else {
            printf("[-] unknown float size\n");
            throw std::exception();
        }
        return;
    }
    if(ty->kind == TK_Void) {
        auto *voidTy = (VoidType *) ty;
        ss << 'X';
        return;
    }
    if(ty->kind == TK_Winapi) {
        auto *winTy = (WinapiType *) ty;
        mangleTagTypeKind(ss, winTy);
        mangleName(ss, winTy->name, backReference);
        ss << "@";
        return;
    }
    if(ty->kind == TK_Struct) {
        auto *structTy = (StructType *) ty;
        mangleTagTypeKind(ss, structTy);
        // source name
        mangleName(ss, structTy->struc->name, backReference);
        // nested names
        mangleName(ss, "dk2", backReference);
        ss << "@";
        return;
    }
    if(ty->kind == TK_Function) {
        auto *funTy = (FunctionType *) ty;
//        std::vector<std::string> args;
//        for(auto *arg : funTy->args) {
//            args.emplace_back(format_type(arg));
//        }
//        if(funTy->declspec == DS_cdecl_varargs) args.emplace_back("...");
//        std::string argsStr = join(args.begin(), args.end());
//        assert(isPtr);
//        assert(!name.empty());
        mangleFunction(ss, nullptr, funTy, backReference);

        return;
    }
    if(ty->kind == TK_Array) {
        auto *arrTy = (ArrayType *) ty;
        ss << 'P';
        mangleQualifiers(ss, arrTy, false);
        mangleType(ss, arrTy->type, backReference);
        return;
    }
    printf("[-] unknown type kind\n");
    throw std::exception();
}

void mangleFunctionArgumentType(std::stringstream &ss, Type *ty, std::map<std::string, size_t> &backReference, std::map<TypeRef, size_t> &argBackReference) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l02272
    auto it = argBackReference.find(TypeRef(ty));
    if(it != argBackReference.end()) {
        ss << it->second;
    } else {
        auto outSizeBefore = ss.tellp();
        mangleType(ss, ty, backReference);
        bool longerThanOneChar = ((ss.tellp() - outSizeBefore) > 1);
        if(longerThanOneChar && argBackReference.size() < 10) {
            argBackReference[TypeRef(ty)] = argBackReference.size();
        }
    }
}

void mangleFunctionClass(std::stringstream &ss, Struct *member_of, FunctionType *fun) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l02916
    if(member_of) {
        // everything is public
//        auto &v = member_of->vtable_values;
//        bool isVirtual = std::find(v.begin(), v.end(), global->va) != v.end();
        bool isVirtual = false;
        ss << (isVirtual ? 'U' : 'Q');  // Q # public: near  U # public: virtual near
        return;
    }
    ss << 'Y';  // global near
}
void mangleFunction(std::stringstream &ss, Struct *member_of, FunctionType *fun, std::map<std::string, size_t> &backReference) {
    https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l02733
    mangleType(ss, fun->ret, backReference);

    std::map<TypeRef, size_t> argBackReference;
    auto it = fun->args.begin();
    auto end = fun->args.end();
    if(member_of != nullptr) {
        if(it != end) {
            ++it;
        }
    }
    bool hasNoArgs = it == end;
    for(;it != end; ++it) {
        mangleFunctionArgumentType(ss, *it, backReference, argBackReference);
    }

    if(hasNoArgs && fun->cconv != DS_cdecl_varargs) {  // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l02854
        ss << 'X';
    } else if(fun->cconv == DS_cdecl_varargs) {
        ss << 'Z';
    } else {
        ss << '@';
    }
    ss << 'Z';
}
void mangleGlobal(std::stringstream &ss, Global *global, std::map<std::string, size_t> &backReference) {
    // https://clang.llvm.org/doxygen/MicrosoftMangle_8cpp_source.html#l00622
    // <storage-class> ::= 0  # private static member
    //                 ::= 1  # protected static member
    //                 ::= 2  # public static member
    //                 ::= 3  # global
    //                 ::= 4  # static local

    if(global->name.ends_with("_vftable")) {
        // assume all vftable as void *[?]
        ss << "2";  // # public static member
        ss << 'P';
        ss << 'A';
        ss << 'P';
        ss << 'A';
        ss << 'X';
    } else {
        ss << "3";  // # global
        mangleType(ss, global->type, backReference);
    }

    mangleQualifiers(ss, global->type, false);
}
std::string msvcMangleName(Global *global) {
    if(global->type->kind == TK_Function && global->member_of != nullptr) {
        std::string &structName = global->member_of->name;
        auto *fun = (FunctionType *) global->type;
        switch (fun->cxx) {
        case CXXF_Regular: break;
        case CXXF_Constructor: break;
        case CXXF_Destructor: break;
        case CXXF_CopyConstructor: return "??0" + structName + "@dk2@@QAE@ABU01@@Z";
        case CXXF_MoveConstructor: break;
        case CXXF_CopyAssign: break;
        case CXXF_MoveAssign: break;
        }
    }
    std::vector<std::string> names;
    names.emplace_back("dk2");  // namespace
    if(global->name.ends_with("_vftable")) {
        names.emplace_back(global->name.substr(0, global->name.size() - strlen("_vftable")));  // class
        names.emplace_back("vftable");  // member name
    } else {
        if(global->member_of != nullptr) {
            names.emplace_back(global->member_of->name);  // class
        }
        names.emplace_back(global->name);  // global name
    }

    std::stringstream ss;
    ss << "?";
    std::map<std::string, size_t> backReference;
    for(auto &name : names | std::views::reverse) {
        ss << name << "@";
        backReference[name] = backReference.size();
    }

    ss << "@";
    if(global->type->kind == TK_Function) {
        auto *fun = (FunctionType *) global->type;
        mangleFunctionClass(ss, global->member_of, fun);
        if(global->member_of != nullptr) {
            mangleQualifiers(ss, fun, false);
        }
        mangleCConv(ss, fun->cconv);
        mangleFunction(ss, global->member_of, fun, backReference);
    } else {
        mangleGlobal(ss, global, backReference);
    }
    return ss.str();
}
