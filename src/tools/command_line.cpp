//
// Created by DiaLight on 19.01.2025.
//
#include "command_line.h"

#include <Windows.h>
#include <iostream>
#include <stdexcept>
#include <algorithm>


void toLowerCase(std::string &str) {
    std::transform(str.begin(), str.end(), str.begin(),
        [](unsigned char c){ return std::tolower(c); });
}

void parseCommandLine(int argc, const char **argv, std::map<std::string, std::string> &dict, std::vector<std::string> &flags, std::vector<std::string> &values) {
    const char **begin = argv;
    const char **end = argv + argc;
    std::string key;
    for (const char **it = begin; it < end; it++) {
        const char *arg = *it;
        const char *value = nullptr;
        if (arg[0] == '-' || arg[0] == '/') {  // is key
            if (!key.empty()) {
                flags.push_back(key);
                key.clear();
            }
            arg += 1;
            const char *eq = strchr(arg, '=');
            if (eq) {  // arg contains value
                key.assign(arg, eq - arg);
                value = eq + 1;
            } else {
                key.assign(arg);
            }
            toLowerCase(key);
            if (!value) continue;
        } else {
            if (key.empty()) {
                values.emplace_back(arg);
                continue;
            }
            value = arg;
        }
        // if (dict.contains(key)) {
        //     // do we need support for multiple values?
        // }
        dict[key] = value;
        key.clear();
    }
    if (!key.empty()) {
        flags.push_back(key);
        key.clear();
    }
}

namespace cmdl {
    std::map<std::string, std::string> dict;
    std::vector<std::string> flags;
    std::vector<std::string> values;
}

bool cmdl::hasFlag(const std::string &flag) {
    return std::find(flags.begin(), flags.end(), flag) != flags.end();
}
void cmdl::dump() {
    if (!dict.empty()) {
        std::cout << "options:" << std::endl;
        for (const auto &it : dict) {
            std::cout << " " << it.first << ": " << it.second << std::endl;
        }
    }
    if (!flags.empty()) {
        std::cout << "flags:" << std::endl;
        for (const auto &it : flags) {
            std::cout << " " << it << std::endl;
        }
    }
    if (!values.empty()) {
        std::cout << "values:" << std::endl;
        for (const auto &it : values) {
            std::cout << " " << it << std::endl;
        }
    }
}


void command_line_init(int argc, const char **argv) {
    parseCommandLine(argc, argv, cmdl::dict, cmdl::flags, cmdl::values);
}

