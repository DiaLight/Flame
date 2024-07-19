//
// Created by DiaLight on 23.06.2024.
//
#include "LineIter.h"
#include <string>

std::string *LineIter::next() {
    if(use_last) {
        use_last = false;
        return &line;
    }
    if (std::getline(is, line)) {
        line_num++;
        return &line;
    }
    return nullptr;
}
