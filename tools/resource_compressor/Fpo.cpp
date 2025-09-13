//
// Created by DiaLight on 9/5/2025.
//

#include "Fpo.h"
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>


#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << val << std::dec

std::ostream &operator<< (std::ostream &os, const FpoFun& r) {
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

void parseStack(std::istream &is, std::vector<FpoFun> &vec) {
    FpoFun *fpo = nullptr;
    std::string line;
    while(is) {
        if (!getlineOpt(is, line)) break;
        if(line.starts_with("#")) continue;
        if(line.ends_with("\n")) line.resize(line.size() - 1);
        if(line.ends_with("\r")) line.resize(line.size() - 1);
        if(line.empty()) continue;
        if(!line.starts_with(" ")) {
            std::string va;
            std::string name;
            std::stringstream iss(line);
            if (!std::getline(iss, va, ' ')
                || !std::getline(iss, name)) {
                is.setstate(iss.rdstate() & (std::ios::badbit | std::ios::failbit));
                std::cout << "failed" << std::endl;
                break;
            }
            fpo = &vec.emplace_back();
            fpo->va = std::stoul(va, nullptr, 16);
            fpo->name = name;
        } else {
            if(fpo == nullptr) {
                is.setstate(std::ios::failbit);
                std::cout << "failed" << std::endl;
                break;
            }
            line = line.substr(1);
            std::string va;
            std::string spd;
            std::string kind;
            std::string delta;
            std::string cmt;
            std::stringstream iss(line);
            if (
                !std::getline(iss, va, ' ')
                || !std::getline(iss, spd, ' ')
                || !std::getline(iss, kind, ' ')
                || !std::getline(iss, delta, ' ')) {
                is.setstate(iss.rdstate() & (std::ios::badbit | std::ios::failbit));
                std::cout << "failed" << std::endl;
                break;
            }
            getlineOpt(iss, cmt); // optional
            int kind_;
            if (kind == "sp") {
                kind_ = 0;
            } else if (kind == "jmp") {
                kind_ = 1;
            } else if (kind == "ret") {
                kind_ = 2;
            } else {
                is.setstate(std::ios::failbit);
                std::cout << "failed" << std::endl;
            }
            uint32_t va_ = std::stoul(va, nullptr, 16);
            int offs = va_ - fpo->va;
            fpo->_update_size(offs + 1);
            fpo->spds.emplace_back(
                offs,
                -std::stol(spd),
                SPD_Ida,
                kind_
            );
        }
    }
}
bool parseStack(const std::string &path, std::vector<FpoFun> &vec) {
    std::ifstream is(path);
    parseStack(is, vec);
    return is.eof();
}
