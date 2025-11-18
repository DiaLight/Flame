//
// Created by DiaLight on 9/5/2025.
//

#include "Symbol.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>


#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << val << std::dec

std::ostream &operator<< (std::ostream &os, const Symbol& r) {
    std::ostream &os1 = os << fmtHex32(r.va) << " " << r.name;
    return os1;
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
std::istream& operator>>(std::istream &is, Symbol& data) {
    std::string va;
    std::string name;
    std::string replace;
    if (!std::getline(is, va, ' ')
        || !std::getline(is, name, ' ')) {
        std::cout << "failed" << std::endl;
        return is;
    }
    getlineOpt(is, replace);
    data.va = std::stoul(va, nullptr, 16);
    data.name = name;
    if (!replace.empty()) {
        if (replace != "REPLACE") {
            std::cout << "failed" << std::endl;
            is.setstate(std::ios::failbit);
            return is;
        }
        data.replace = true;
    }
    return is;
}

void parseSymbols(std::istream &is, std::vector<Symbol> &vec, const std::function<void(int cur, int max)> &progress) {
    is.seekg(0, std::ios::end);
    auto end = is.tellg();
    is.seekg(0, std::ios::beg);
    while(!is.eof()) {
        progress(is.tellg(), end);
        std::string line;
        while(getlineOpt(is, line)) {
            if(line.starts_with("#")) continue;
            if(line.ends_with("\n")) line.resize(line.size() - 1);
            if(line.ends_with("\r")) line.resize(line.size() - 1);
            if(line.empty()) continue;
            break;
        }
        if(line.empty()) break;
        std::stringstream iss(line);
        Symbol r;
        iss >> r;
        if(!iss) {
            is.setstate(iss.rdstate() & (std::ios::badbit | std::ios::failbit));
            break;
        }
        vec.push_back(r);
    }
}

std::vector<Symbol>::iterator find_gt(std::vector<Symbol> &vec, uint32_t va) {
    return std::upper_bound(vec.begin(), vec.end(), va, [](uint32_t va, Symbol &bl) {  // <
        return va < bl.va;
    });
}

std::vector<Symbol>::iterator find_ge(std::vector<Symbol> &vec, uint32_t va) {
    return std::lower_bound(vec.begin(), vec.end(), va, [](Symbol &bl, uint32_t va) {  // <=
        return bl.va < va;
    });
}

std::vector<Symbol>::iterator find_lt(std::vector<Symbol> &vec, uint32_t offs) {
    auto it = find_ge(vec, offs);
    if (it == vec.begin()) return vec.end();
    return it - 1;
}

std::vector<Symbol>::iterator find_le(std::vector<Symbol> &vec, uint32_t offs) {
    auto it = find_gt(vec, offs);
    if (it == vec.begin()) return vec.end();
    return it - 1;
}
