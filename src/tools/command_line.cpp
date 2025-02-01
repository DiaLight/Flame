//
// Created by DiaLight on 19.01.2025.
//
#include "command_line.h"
#include <Windows.h>

namespace cmdl {
    int argc = 0;
    const char **argv = NULL;
}

void command_line_init(int argc, const char **argv) {
    cmdl::argc = argc;
    cmdl::argv = argv;
}

bool hasCmdOption(const std::string &option) {
    const char **begin = cmdl::argv;
    const char **end = cmdl::argv + cmdl::argc;
    return std::find(begin, end, option) != end;
}

const char *getCmdOption(const std::string &option) {
    const char **begin = cmdl::argv;
    const char **end = cmdl::argv + cmdl::argc;
    const char **it = std::find(begin, end, option);
    if (it != end && ++it != end) return *it;
    return nullptr;
}
