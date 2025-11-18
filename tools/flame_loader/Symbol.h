//
// Created by DiaLight on 9/5/2025.
//

#ifndef FLAME_SYMBOL_H
#define FLAME_SYMBOL_H


#include <utility>
#include <vector>
#include <string>
#include <functional>


struct Symbol {
    uint32_t va = 0;
    std::string name;
    bool replace = false;

    Symbol() = default;
    Symbol(uint32_t va, std::string name, bool replace) : va(va), name(std::move(name)), replace(replace) {}
};

void parseSymbols(std::istream &is, std::vector<Symbol> &syms, const std::function<void(int cur, int max)> &progress);

std::vector<Symbol>::iterator find_gt(std::vector<Symbol> &syms, uint32_t offs);
std::vector<Symbol>::iterator find_ge(std::vector<Symbol> &syms, uint32_t offs);
std::vector<Symbol>::iterator find_lt(std::vector<Symbol> &syms, uint32_t offs);
std::vector<Symbol>::iterator find_le(std::vector<Symbol> &syms, uint32_t offs);



#endif // FLAME_SYMBOL_H
