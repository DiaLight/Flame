//
// Created by DiaLight on 9/17/2025.
//

#include "StackFrame.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <ranges>

#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex16(val) std::hex << std::setw(4) << std::setfill('0') << std::uppercase << (val) << std::dec
#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec
#define fmtHex(val) std::hex << std::uppercase << (val) << std::dec



std::ostream &operator<<(std::ostream &os, const StackFrame &frame) {
    os << "ebp=" << fmtHex32(frame.ebp);
    os << " esp=" << fmtHex32(frame.esp);
    os << " eip=" << fmtHex32(frame.eip);
    os << " ";
    if(!frame.libName.empty()) {
        os << std::right << std::setw(16) << std::setfill(' ') << frame.libName << ":";
    } else if(frame.libBase) {
        os << std::right << std::setw(16) << std::setfill(' ') << fmtHex32(frame.libBase) << ":";
    }
    if(!frame.symName.empty()) {
        os << StackFrame_getReadableSymName(frame.symName);
        os << "+" << fmtHex(frame.eip - frame.symAddr);
    } else {
        os << "base";
        os << "+" << fmtHex(frame.eip - frame.libBase);
    }
    if(frame.symName.starts_with('?')) {
        os << " (" << frame.symName << ")";
    }
    return os;
}


void StackFrame::reset() {
    eip = 0;
    esp = 0;
    ebp = 0;
    libName.clear();
    libBase = 0;
    symName.clear();
    symAddr = 0;
}

std::string StackFrame_getReadableSymName(const std::string &symName) {
    if(symName.starts_with('?')) {
        std::vector<std::pair<size_t, size_t>> parts;
        std::pair<size_t, size_t> suffix(0, 0);
        size_t offs = 1;
        while(true) {
            size_t pos = symName.find('@', offs);
            if(pos == std::string::npos) break;
            if(pos == offs) {
                suffix = {offs + 2, symName.size() - offs};
                break;
            }
            parts.emplace_back(offs, pos - offs);
            offs = pos + 1;
        }
        std::stringstream ss;
        for(auto &part : parts | std::views::reverse) {
            if(ss.tellp()) ss << "::";
            ss << symName.substr(part.first, part.second);
        }
        //        if(suffix.first) {
        //            ss << "(";
        //            ss << symName.substr(suffix.first, suffix.second);
        //            ss << ")";
        //        }
        return ss.str();
    }
    return symName;
}
