//
// Created by DiaLight on 23.06.2024.
//

#ifndef FLAME_LINEITER_H
#define FLAME_LINEITER_H

#include <fstream>

struct LineIter {

    std::istream &is;
    std::string line;
    size_t line_num = 0;
    bool use_last = false;

    explicit LineIter(std::istream &is) : is(is) {}

    std::string *next();

};

#endif //FLAME_LINEITER_H
