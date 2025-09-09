//
// Created by DiaLight on 30.06.2024.
//

#ifndef FLAME_VARELOC_H
#define FLAME_VARELOC_H

#include <vector>
#include <string>


struct VaReloc {
    enum RelocType {
        RT_VA32,
        RT_REL32,
    };

    uint32_t from = 0;
    uint32_t value = 0;
    uint32_t to = 0;
    RelocType ty = RT_VA32;

    VaReloc() = default;
    VaReloc(uint32_t from, uint32_t value, uint32_t to, RelocType ty) : from(from), value(value), to(to), ty(ty) {}
};

void parseRelocs(std::istream &is, std::vector<VaReloc> &relocs);
bool parseRelocs(const std::string &path, std::vector<VaReloc> &relocs);

std::vector<VaReloc>::iterator find_gt(std::vector<VaReloc> &relocs, uint32_t offs);
std::vector<VaReloc>::iterator find_ge(std::vector<VaReloc> &relocs, uint32_t offs);
std::vector<VaReloc>::iterator find_lt(std::vector<VaReloc> &relocs, uint32_t offs);
std::vector<VaReloc>::iterator find_le(std::vector<VaReloc> &relocs, uint32_t offs);


#endif //FLAME_VARELOC_H
