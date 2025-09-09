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
            if(line.starts_with("//")) continue;
            if(line.empty()) continue;

            std::stringstream iss(line);
            std::string rvaStr;
            if ( std::getline(iss, rvaStr, ' ')) {
                try {
                    uint32_t rva = std::stoul(rvaStr, nullptr, 16);
                    globalsToReplace.insert(rva);
                } catch(std::invalid_argument &e) {
                    std::cout << "cant parse int \"" << rvaStr << "\"" << std::endl;
                    exit(-1);
                }
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
    printf("  -asm_stub_file <path>\n");
}

int main(int argc, char * argv[]) {
    if (hasCmdOption(argv, argv + argc, "-h")) {
        show_help();
        return EXIT_SUCCESS;
    }

    char *sgmap_file = getCmdOption(argv, argv + argc, "-sgmap_file");
    if (sgmap_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *def_file = getCmdOption(argv, argv + argc, "-def_file");
    if (def_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *replace_globals = getCmdOption(argv, argv + argc, "-replace_globals");
    if (replace_globals == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *exp_file = getCmdOption(argv, argv + argc, "-exp_file");
    if (exp_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *map_file = getCmdOption(argv, argv + argc, "-map_file");
    if (map_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *asm_stub_file = getCmdOption(argv, argv + argc, "-asm_stub_file");
    if (asm_stub_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    DWORD startMs = GetTickCount();

    printf("Dungeon Keeper 2 genlib\n");
//    printf("sgmap_file %s\n", sgmap_file);
//    printf("def_file %s\n", def_file);
//    printf("replace_globals %s\n", replace_globals);
//    printf("exp_file %s\n", exp_file);
//    printf("map_file %s\n", map_file);
//    printf("asm_stub_file %s\n", asm_stub_file);

    SGMapArena sgArena;
    std::vector<Struct *> structs;
    std::vector<Global *> globals;

    std::set<uint32_t> globalsToReplace;
    {
        {
            std::ifstream is(sgmap_file);
            if (!SGMap_deserialize(is, structs, globals, sgArena)) return EXIT_FAILURE;
            if (!SGMap_link(structs, globals)) return EXIT_FAILURE;
        }
        if (!getGlobalsToReplace(replace_globals, globalsToReplace)) return EXIT_FAILURE;
    }

    {
        std::ofstream def_os(def_file);
        if (!def_os.is_open()) {
            printf("[-] write def mapping failed %s\n", exp_file);
            return EXIT_FAILURE;
        }
        std::ofstream exp_os(exp_file);
        if (!exp_os.is_open()) {
            printf("[-] write exp mapping failed %s\n", exp_file);
            return EXIT_FAILURE;
        }
        std::ofstream map_os(map_file);
        if (!map_os.is_open()) {
            printf("[-] write symbol mapping failed %s\n", map_file);
            return EXIT_FAILURE;
        }
        std::ofstream asm_os(asm_stub_file);
        if (!asm_os.is_open()) {
            printf("[-] write asm stub failed %s\n", asm_stub_file);
            return EXIT_FAILURE;
        }
        def_os << "LIBRARY DKII" << std::endl;
        def_os << "EXPORTS" << std::endl;
//        exp_os << "LIBRARY DKII-Flame" << std::endl;
        exp_os << "EXPORTS" << std::endl;

        asm_os << ".386" << std::endl;
        asm_os << ".model flat" << std::endl;
        asm_os << ".code" << std::endl;
        asm_os << std::endl;

        bool hasBadSymbols = false;
        for (auto *global: globals | std::views::reverse) {
            bool isReplace = globalsToReplace.contains(global->va);
            auto name = msvcMangleName(global);
            if(name.contains(':')) {
                printf("[-] symbol %s has ':' in name\n", name.c_str());
                hasBadSymbols = true;
            }

            std::ofstream &os = isReplace ? exp_os : def_os;
            os << "   " << name;
            if(global->type->kind != TK_Function) {
                os << " DATA";
            }
            os << std::endl;
            map_os << fmtHex32(global->va) << " " << name;
            if(isReplace) map_os << " REPLACE";
            map_os << std::endl;

            asm_os << name << " proc EXPORT\n";
            asm_os << name << " endp\n";
        }
        def_os << std::endl;
        exp_os << std::endl;
        map_os << std::endl;

        asm_os << "    xor eax,eax" << std::endl;
        asm_os << "    ret" << std::endl;
        asm_os << "end" << std::endl;

        if(hasBadSymbols) return EXIT_FAILURE;
    }

    printf("finished in %lu ms\n", GetTickCount() - startMs);
    return EXIT_SUCCESS;
}
