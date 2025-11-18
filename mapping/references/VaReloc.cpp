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

namespace {
    bool getlineOpt(std::istream &is, std::string &line) {
        if(is.fail()) return false;
        if(!std::getline(is, line)) {
            is.clear(is.rdstate() & ~std::ios::failbit);
            return false;
        }
        return true;
    }
}

std::istream& operator>>(std::istream &is, VaReloc& data) {
    std::string vaFr;
    std::string value;
    std::string vaTo;
    std::string ty;
    if (!std::getline(is, vaFr, ' ')
        || !std::getline(is, value, ' ')
        || !std::getline(is, vaTo, ' ')
        || !std::getline(is, ty)) {
        std::cout << "failed" << std::endl;
        return is;
    }
    data.from = std::stoul(vaFr, nullptr, 16);
    data.value = std::stoul(value, nullptr, 16);
    data.to = std::stoul(vaTo, nullptr, 16);
    if (ty == "VA32") {
        data.ty = VaReloc::RT_VA32;
    } else if (ty == "REL32") {
        data.ty = VaReloc::RT_REL32;
    } else if (ty == "!VA32") {
        data.ty = VaReloc::RT_NOT_VA32;
//            std::cout << vaFr << " -> " << vaTo << " " << ty << std::endl;
    } else {
        std::cout << "failed" << std::endl;
        is.setstate(std::ios::failbit);
    }
    return is;
}

void parseRelocs(std::istream &is, std::vector<VaReloc> &relocs, const std::function<void(int cur, int max)> &progress) {
    is.seekg(0, std::ios::end);
    auto end = is.tellg();
    is.seekg(0, std::ios::beg);
    std::string line;
    while(!is.eof()) {
        progress(is.tellg(), end);
        while(getlineOpt(is, line)) {
            if(line.starts_with("#")) continue;
            if(line.ends_with("\n")) line.resize(line.size() - 1);
            if(line.ends_with("\r")) line.resize(line.size() - 1);
            if(line.empty()) continue;
            break;
        }
        if(line.empty()) break;
        std::stringstream iss(line);
        VaReloc r;
        iss >> r;
        if(!iss) {
            is.setstate(iss.rdstate() & (std::ios::badbit | std::ios::failbit));
            break;
        }
        relocs.push_back(r);
    }
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
