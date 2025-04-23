//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_COMMAND_LINE_H
#define FLAME_COMMAND_LINE_H

#include <string>
#include <map>
#include <vector>

void toLowerCase(std::string &str);

namespace cmdl {
    extern std::map<std::string, std::string> dict;
    extern std::vector<std::string> flags;
    extern std::vector<std::string> values;

    bool hasFlag(const std::string &flag);
    void dump();
}

void command_line_init(int argc, const char **argv);


#endif //FLAME_COMMAND_LINE_H
