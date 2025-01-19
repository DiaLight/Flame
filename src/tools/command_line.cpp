//
// Created by DiaLight on 19.01.2025.
//
#include "command_line.h"
#include <Windows.h>


bool hasCmdOption(const char **begin, const char **end, const std::string &option) {
    return std::find(begin, end, option) != end;
}

const char *getCmdOption(const char **begin, const char **end, const std::string &option) {
    const char **it = std::find(begin, end, option);
    if (it != end && ++it != end) return *it;
    return nullptr;
}


bool hasCmdOption(const std::string &option) {
    LPSTR lpCommandLine = GetCommandLineA();
    char* token = strtok(lpCommandLine, " ");
    while (token != nullptr) {
        if (std::string(token) == option) return true;
        token = strtok(nullptr, " ");
    }

    return false;
}

std::string getCmdOption(const std::string &option) {
    LPSTR lpCommandLine = GetCommandLineA();
    char* token = strtok(lpCommandLine, " ");
    while (token != nullptr) {
        if (std::string(token) == option) {
            token = strtok(nullptr, " ");
            if (token != nullptr) {
                return std::string(token);
            }
        } else {
            token = strtok(nullptr, " ");
        }
    }
    return "";
}
