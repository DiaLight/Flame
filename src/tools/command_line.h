//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_COMMAND_LINE_H
#define FLAME_COMMAND_LINE_H

#include <string>


bool hasCmdOption(const char **begin, const char **end, const std::string &option);
const char *getCmdOption(const char **begin, const char **end, const std::string &option);

bool hasCmdOption(const std::string &option);
std::string getCmdOption(const std::string &option);


#endif //FLAME_COMMAND_LINE_H
