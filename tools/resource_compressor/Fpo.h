//
// Created by DiaLight on 9/5/2025.
//

#ifndef FLAME_FPO_H
#define FLAME_FPO_H


#include <utility>
#include <vector>
#include <string>


enum SpdType {
    SPD_Ida,
    SPD_Fpo,
    SPD_Frm,
};


struct Spd {  // Stack pointer delta
    size_t offs = 0;
    int spd = 0;
    SpdType ty = SPD_Fpo;
    int kind = 0;

    Spd() = default;
    Spd(size_t offs, int spd, SpdType ty, int kind) : offs(offs), spd(spd), ty(ty), kind(kind) {}
};
struct FpoFun {
    uint32_t va = 0;
    std::string name;
    size_t size = 0;
    std::vector<Spd> spds;

    FpoFun() = default;
    FpoFun(uint32_t va, std::string name, size_t size) : va(va), name(std::move(name)), size(size) {}

    void _update_size(size_t size) {
        if(size > this->size) this->size = size;
    }

};

void parseStack(std::istream &is, std::vector<FpoFun> &syms);
bool parseStack(const std::string &path, std::vector<FpoFun> &syms);



#endif // FLAME_FPO_H
