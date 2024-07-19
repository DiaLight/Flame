//
// Created by DiaLight on 30.06.2024.
//

#include "VaReloc.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>


#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << val << std::dec

std::ostream &operator<< (std::ostream &os, const VaReloc& r) {
    std::ostream &os1 = os << fmtHex32(r.from) << " "  << fmtHex32(r.value) << " -> " << fmtHex32(r.to) << " ";
    switch(r.ty) {
        case VaReloc::RT_VA32: return os1 << "VA32";
        case VaReloc::RT_REL32: return os1 << "REL32";
    }
    return os1 << "<unk>";
}

std::istream& operator>>(std::istream &is, VaReloc& data) {
    std::string line;
    while(true) {
        if (std::getline(is, line)) {
            if(line.starts_with("#")) continue;
            if(line.empty()) continue;
            std::stringstream iss(line);
            std::string vaFr;
            std::string value;
            std::string vaTo;
            std::string ty;
            if ( std::getline(iss, vaFr, ' ') &&
                 std::getline(iss, value, ' ') &&
                 std::getline(iss, vaTo, ' ') &&
                 std::getline(iss, ty)) {
                data.from = std::stoul(vaFr, nullptr, 16);
                data.value = std::stoul(value, nullptr, 16);
                data.to = std::stoul(vaTo, nullptr, 16);
                if(ty == "VA32") {
                    data.ty = VaReloc::RT_VA32;
                } else if(ty == "REL32") {
                    data.ty = VaReloc::RT_REL32;
                } else if(ty == "!VA32") {
//                    std::cout << vaFr << " -> " << vaTo << " " << ty << std::endl;
                    continue;
                } else {
                    std::cout << "failed" << std::endl;
                    is.setstate(std::ios::failbit);
                }
            } else {
                std::cout << "failed" << std::endl;
                is.setstate(std::ios::failbit);
            }
        }
        return is;
    }
}

bool parseRelocs(const std::string &path, std::vector<VaReloc> &relocs) {
    std::ifstream is(path);
    while(true) {
        VaReloc r;
        is >> r;
        if(!is) break;
        relocs.push_back(r);
    }
    return is.eof();
}

std::vector<VaReloc>::iterator find_gt(std::vector<VaReloc> &relocs, uint32_t offs) {
    return std::upper_bound(relocs.begin(), relocs.end(), offs, [](uint32_t offs, VaReloc &bl) {  // <
        return offs < bl.from;
    });
}

std::vector<VaReloc>::iterator find_ge(std::vector<VaReloc> &relocs, uint32_t offs) {
    return std::lower_bound(relocs.begin(), relocs.end(), offs, [](VaReloc &bl, uint32_t offs) {  // <=
        return bl.from < offs;
    });
}

std::vector<VaReloc>::iterator find_lt(std::vector<VaReloc> &relocs, uint32_t offs) {
    auto it = find_ge(relocs, offs);
    if (it == relocs.begin()) return relocs.end();
    return it - 1;
}

std::vector<VaReloc>::iterator find_le(std::vector<VaReloc> &relocs, uint32_t offs) {
    auto it = find_gt(relocs, offs);
    if (it == relocs.begin()) return relocs.end();
    return it - 1;
}
