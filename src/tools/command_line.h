//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_COMMAND_LINE_H
#define FLAME_COMMAND_LINE_H

#include <string>

void command_line_init(int argc, const char **argv);

bool hasCmdOption(const std::string &option);
const char *getCmdOption(const std::string &option);


#endif //FLAME_COMMAND_LINE_H
