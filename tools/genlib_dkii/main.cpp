//
// Created by DiaLight on 01.09.2024.
//
#include <Windows.h>
#include <fstream>
#include <string>
#include <vector>
#include <ranges>
#include <filesystem>
#include <set>
#include <iostream>
#include "SGMap.h"
#include "msvc_mangler.h"

#define fmtHex32(val) std::hex << std::setw(8) << std::setfill('0') << std::uppercase << val << std::dec
#define fmtHex16(val) std::hex << std::setw(4) << std::setfill('0') << std::uppercase << val << std::dec


char *getCmdOption(char **begin, char **end, const std::string &option) {
    char **it = std::find(begin, end, option);
    if (it != end && ++it != end) return *it;
    return nullptr;
}

bool hasCmdOption(char **begin, char **end, const std::string &option) {
    return std::find(begin, end, option) != end;
}

bool getGlobalsToReplace(const std::string &path, std::set<uint32_t> &globalsToReplace) {
    std::ifstream is(path);
    std::string line;
    while(is) {
        if (std::getline(is, line)) {
            if(line.starts_with("#")) continue;
            if(line.empty()) continue;

            std::stringstream iss(line);
            std::string rva;
            if ( std::getline(iss, rva, ' ')) {
                globalsToReplace.insert(std::stoul(rva, nullptr, 16));
            } else {
                std::cout << "failed" << std::endl;
                is.setstate(std::ios::failbit);
            }
        }
    }
    if(!is.eof()) {
        printf("[-] failed to collect globals to replace. %s\n", path.c_str());
        return false;
    }
    return true;
}

void show_help() {
    printf("genlib_dkii\n");
    printf("  -sgmap_file <path>\n");
    printf("  -def_file <path>\n");
    printf("  -replace_globals <path>\n");
    printf("  -exp_file <path>\n");
    printf("  -map_file <path>\n");
}

int main(int argc, char * argv[]) {
    if (hasCmdOption(argv, argv + argc, "-h")) {
        show_help();
        return 0;
    }

    char *sgmap_file = getCmdOption(argv, argv + argc, "-sgmap_file");
    if (sgmap_file == nullptr) {
        show_help();
        return -1;
    }

    char *def_file = getCmdOption(argv, argv + argc, "-def_file");
    if (def_file == nullptr) {
        show_help();
        return -1;
    }

    char *replace_globals = getCmdOption(argv, argv + argc, "-replace_globals");
    if (replace_globals == nullptr) {
        show_help();
        return -1;
    }

    char *exp_file = getCmdOption(argv, argv + argc, "-exp_file");
    if (exp_file == nullptr) {
        show_help();
        return -1;
    }

    char *map_file = getCmdOption(argv, argv + argc, "-map_file");
    if (map_file == nullptr) {
        show_help();
        return -1;
    }

    DWORD startMs = GetTickCount();

    printf("Dungeon Keeper 2 genlib\n");
//    printf("sgmap_file %s\n", sgmap_file);
//    printf("def_file %s\n", def_file);
//    printf("replace_globals %s\n", replace_globals);
//    printf("exp_file %s\n", exp_file);
//    printf("map_file %s\n", map_file);

    SGMapArena sgArena;
    std::vector<Struct *> structs;
    std::vector<Global *> globals;

    std::set<uint32_t> globalsToReplace;
    {
        {
            std::ifstream is(sgmap_file);
            if (!SGMap_deserialize(is, structs, globals, sgArena)) return -1;
            if (!SGMap_link(structs, globals)) return -1;
        }
        if (!getGlobalsToReplace(replace_globals, globalsToReplace)) return -1;
    }

    {
        std::ofstream def_os(def_file);
        if (!def_os.is_open()) {
            printf("[-] write def mapping failed %s\n", exp_file);
            return -1;
        }
        std::ofstream exp_os(exp_file);
        if (!exp_os.is_open()) {
            printf("[-] write exp mapping failed %s\n", exp_file);
            return -1;
        }
        std::ofstream map_os(map_file);
        if (!map_os.is_open()) {
            printf("[-] write symbol mapping failed %s\n", map_file);
            return -1;
        }
        def_os << "LIBRARY DKII" << std::endl;
        def_os << "EXPORTS" << std::endl;
//        exp_os << "LIBRARY DKII-Flame" << std::endl;
        exp_os << "EXPORTS" << std::endl;
        for (auto *global: globals | std::views::reverse) {
            bool isReplace = globalsToReplace.contains(global->va);
            auto name = msvcMangleName(global);
            std::ofstream &os = isReplace ? exp_os : def_os;
            os << "   " << name;
            if(global->type->kind != TK_Function) {
                os << " DATA";
            }
            os << std::endl;
            map_os << fmtHex32(global->va) << " " << name;
            if(isReplace) map_os << " REPLACE";
            map_os << std::endl;
        }
        def_os << std::endl;
        exp_os << std::endl;
        map_os << std::endl;
    }

    printf("finished in %lu ms\n", GetTickCount() - startMs);
    return 0;
}
