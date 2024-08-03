#include <fstream>
#include <string>
#include <vector>
#include <ranges>
#include <filesystem>
#include <set>
#include "chunk/Chunk.h"
#include "dk2.h"
#include "CoffBuilder.h"
#include "SGMap.h"
#include "chunk/ChunkArena.h"
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

bool readBinaryFile(const std::string &path, std::vector<uint8_t> &data) {
    if(!std::filesystem::exists(path)) {
        printf("[-] file %s is not exist\n", path.c_str());
        return false;
    }
    size_t fsize = std::filesystem::file_size(path);
    std::fstream is(path, std::ifstream::in | std::ios::binary);
    data.resize(fsize);
    if(fsize != 0) is.read((char *) &data.front(), fsize);
    return !data.empty();
}

bool writeBinaryFile(const std::string &path, std::vector<uint8_t> &data) {
    std::fstream os(path, std::ifstream::out | std::ios::binary);
    if(!data.empty()) os.write((char *) &data.front(), data.size());
    return os.good();
}

std::vector<Chunk *>::iterator find_gt(std::vector<Chunk *> &chunks, uint32_t offs) {
    return std::upper_bound(chunks.begin(), chunks.end(), offs, [](uint32_t offs, Chunk *&chunk) {  // <
        return offs < chunk->va;
    });
}

std::vector<Chunk *>::iterator find_le(std::vector<Chunk *> &chunks, uint32_t offs) {
    auto it = find_gt(chunks, offs);
    if (it == chunks.begin()) return chunks.end();
    return it - 1;
}

bool insert(std::vector<Chunk *> &vec, Chunk *value) {
    auto it = find_gt(vec, value->va);
    if (it != vec.begin() && (*(it - 1))->va == value->va) {
//        *(it - 1) = value;
        return false;
    }
    if (it == vec.end()) {
        vec.push_back(value);
        return true;
    }
    vec.insert(it, value);
    return true;
}


bool getSizeForStdcallStackArgs(const std::string &path, std::map<std::string, int> &stdcallArgsSizes) {
    std::ifstream is(path);
    std::string line;
    while(is) {
        if (std::getline(is, line)) {
            if(line.starts_with("#")) continue;
            if(line.empty()) continue;

            std::stringstream iss(line);
            std::string name;
            std::string size;
            if ( std::getline(iss, name, ' ') &&
                 std::getline(iss, size)) {
                stdcallArgsSizes.insert(std::make_pair(name, std::stoul(size)));
            } else {
                std::cout << "failed" << std::endl;
                is.setstate(std::ios::failbit);
            }
        }
    }
    return is.eof();
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
int getSizeForStdcallStackArgs(std::map<std::string, int> &stdcallArgsSizes, const std::string &name) {
    auto it = stdcallArgsSizes.find(name);
    if(it == stdcallArgsSizes.end()) {
        printf("[-] stack size not found for api %s\n", name.c_str());
        return -2;
    }
    return it->second;
}

void show_help() {
    printf("delinker\n");
    printf("  -dkii_exe <path>\n");
    printf("  -sgmap_file <path>\n");
    printf("  -references_file <path>\n");
    printf("  -args_sizes <path>\n");
    printf("  -replace_globals <path>\n");
    printf("  -delinked <path>\n");
}

int main(int argc, char * argv[]) {
    if (hasCmdOption(argv, argv + argc, "-h")) {
        show_help();
        return 0;
    }

    char *dkii_exe = getCmdOption(argv, argv + argc, "-dkii_exe");
    if (dkii_exe == nullptr) {
        show_help();
        return -1;
    }

    char *sgmap_file = getCmdOption(argv, argv + argc, "-sgmap_file");
    if (sgmap_file == nullptr) {
        show_help();
        return -1;
    }

    char *references_file = getCmdOption(argv, argv + argc, "-references_file");
    if (references_file == nullptr) {
        show_help();
        return -1;
    }

    char *args_sizes = getCmdOption(argv, argv + argc, "-args_sizes");
    if (args_sizes == nullptr) {
        show_help();
        return -1;
    }

    char *replace_globals = getCmdOption(argv, argv + argc, "-replace_globals");
    if (replace_globals == nullptr) {
        show_help();
        return -1;
    }

    char *delinked_dir = getCmdOption(argv, argv + argc, "-delinked");
    if (delinked_dir == nullptr) {
        show_help();
        return -1;
    }

    DWORD startMs = GetTickCount();

    printf("Dungeon Keeper 2 delinker\n");
    SGMapArena sgArena;
    std::vector<Struct *> structs;
    std::vector<Global *> globals;
    std::vector<Global *> imports;

    ChunkArena arena;
    std::vector<Chunk *> chunks;

    std::map<std::string, int> stdcallArgsSizes;
    std::set<uint32_t> globalsToReplace;
    {
        std::vector<uint8_t> dk2_buf;
        if (!readBinaryFile(dkii_exe, dk2_buf)) return -1;

        if (!collectImports(dk2_buf.data(), imports, sgArena)) return -1;
        std::vector<SectionChunk> sections;
        if (!collectSectionChunks(dk2_buf.data(), sections)) return -1;

        {
            std::ifstream is(sgmap_file);
            if (!SGMap_deserialize(is, structs, globals, sgArena)) return -1;
            if (!SGMap_link(structs, globals)) return -1;
        }

        std::vector<VaReloc> relocs;
        if (!parseRelocs(references_file, relocs)) return -1;

        if (!buildChunks(std::move(sections), std::move(relocs), chunks, arena)) return -1;
        if (!getSizeForStdcallStackArgs(args_sizes, stdcallArgsSizes)) return -1;
        if (!getGlobalsToReplace(replace_globals, globalsToReplace)) return -1;
    }

    auto splitByGlobal = [](std::vector<Chunk *> &chunks, Global *global, ChunkArena &arena) -> Chunk * {
        if (global->size == 0) {
            printf("[-] %08X global with no size\n", global->va);
            return nullptr;
        }
        auto it = find_le(chunks, global->va);
        if (it == chunks.end()) {
            printf("[-] failed to find chunk for global\n");
            return nullptr;
        }
        auto lhs = *it;
        uint32_t chunk_start = lhs->va;
        uint32_t chunk_end = chunk_start + lhs->data.size();
        uint32_t global_end = global->va + global->size;
        if (!(chunk_start <= global->va && global_end <= chunk_end)) {
            printf("[-] interception detected g.%08X <= ch.%08X & ch.%08X <= g.%08X\n",
                   chunk_start, global->va,
                   global_end, chunk_end);
            return nullptr;
        }
        if (auto rhs = lhs->split(global_end - chunk_start, arena)) {
            if (!insert(chunks, rhs)) return nullptr;
        }
        Chunk *ret;
        if (auto chunk = lhs->split(global->va - chunk_start, arena)) {
            if (!insert(chunks, chunk)) return nullptr;
            ret = chunk;
        } else {
            ret = lhs;
        }
        return ret;
    };
    // ida sensitive names
    static auto prefixNeeded = [](Global *global) {
        if (global->name.empty()) return false;
        if (global->name.starts_with("nullsub_")) return true;
        if (global->name.starts_with("j_")) return true;
//        if (global->name.starts_with("sub_")) return true;
        if (global->name.starts_with("def_")) return true;
//        if (global->name.starts_with("_")) return true;
        return false;
    };
    static auto mangleGlobal = [](Global *global) -> std::string {
        // undefined ida symbols
        if (prefixNeeded(global)) return "dk2_" + global->name;
        // user and auto defined names
        return msvcMangleName(global);
    };
    std::vector<Global *> toBecomeSymbols;
    for (auto *global: globals | std::views::reverse) {
        bool isReplace = globalsToReplace.contains(global->va);
//        if (!isReplace && global->va >= 0x0068E000) {  // .data
        if (!isReplace && global->va >= 0x0066C000) {  // .idata/.rdata
            // ignore split all the data
            // make unsplitted globals as symbols
            toBecomeSymbols.push_back(global);
            continue;
        }
        Chunk *chunk = splitByGlobal(chunks, global, arena);
        if (chunk == nullptr) return -1;

        chunk->name = mangleGlobal(global);
        chunk->isJumpTable = global->name.starts_with("jpt_");;
        // executable sections can contain data between functions
        if (chunk->isExecute()) {
            if (global->type->kind != TK_Function) {
                // we need patch chars to link them as data and not as functions
                chunk->chars &= ~IMAGE_SCN_CNT_CODE;
                chunk->chars &= ~IMAGE_SCN_MEM_EXECUTE;
                chunk->chars |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            }
        }
        // move to decompiled chunks that will be replaced
        if (isReplace) {
            chunk->isExcluded = true;
            chunk->objName = "decompiled.obj";  // this obj will not be linked to final exe
        }
    }
    // extract imports to separate obj file
    for (auto *global: imports) {
//        Type *ptrTy = sgArena.types.emplace_back(new VoidType()).get();
//        global->type = sgArena.types.emplace_back(new PtrType(ptrTy, true)).get();
        Chunk *chunk = splitByGlobal(chunks, global, arena);
        if (chunk == nullptr) return -1;
        // building linker compatible import name
        if(chunk->xrefs.empty()) {
            printf("[-] import with no xrefs\n");
            return -1;
        }
        auto *xref = chunk->xrefs[0];
//        uint16_t ins = *(uint16_t *) (xref->chunk->data.data() + xref->rel.offs - 2);
//        printf("%s %d %04X\n", global->name.c_str(), chunk->xrefs.size(), ins);
        if (!global->name.starts_with('?')) {
            chunk->name = "__imp__" + global->name;
            int stackSize = getSizeForStdcallStackArgs(stdcallArgsSizes, global->name);
            if (stackSize == -2) return -1;
            if (stackSize >= 0) {
                chunk->name += "@" + std::to_string(stackSize);
            }
            chunk->objName = "imports.obj";
        } else if(global->name.find("@@3") == std::string::npos) {  // dont generate jmp for data import
            chunk->name = "ij_" + global->name;
            chunk->objSecName = ".ijdata";
//            chunk->chars |= IMAGE_SCN_CNT_CODE;
//            chunk->chars |= IMAGE_SCN_MEM_EXECUTE;
//            chunk->chars &= ~IMAGE_SCN_CNT_INITIALIZED_DATA;

            auto *rhs = arena.chunks.emplace_back(new Chunk()).get();
            rhs->va = global->va;
            rhs->name = global->name;
            rhs->exeSecName = chunk->exeSecName;
            rhs->objSecName = chunk->objSecName;
            rhs->objName = chunk->objName;
            rhs->chars = chunk->chars;
            rhs->objName = "imports.obj";

            auto *ref = chunk->refs.emplace_back(arena.refs.emplace_back(new ChunkRef()).get());
            ref->chunk = rhs;
            ref->rel.offs = 0;
            ref->rel.offsTo = 0;
            ref->rel.type = IMAGE_REL_I386_DIR32;
        } else {  // data import
            chunk->name = "__imp_" + global->name;
            chunk->objName = "imports.obj";
//            chunk->exeSecName = ".rdata";
//            chunk->objSecName = ".rdata";
        }
    }
    // !!! end of chunk splitting !!!

    // fill symbol names
    for(auto *global : toBecomeSymbols) {
        auto it = find_le(chunks, global->va);
        if (it == chunks.end()) {
            printf("[-] failed to find chunk for global\n");
            return -1;
        }
        Chunk *chunk = *it;
        uint32_t offs = global->va - chunk->va;
        if (offs != 0) {
            chunk->symbols[offs] = mangleGlobal(global);
        }
    }
    printf("\n");
    printf("chunks count: %d\n", chunks.size());

    // split by obj name with ignore
    auto ignoreChunk = [](Chunk *chunk) -> bool {
        if(!chunk->name.empty()) return false;
        // ignore empty executable chunks
        if(chunk->isExecute()) {
            if(!chunk->xrefs.empty()) return false;
            if(!chunk->refs.empty()) return false;
            // filled with nop instructions
            for(uint8_t *p = chunk->data.data(), *e = p + chunk->data.size(); p < e; ++p) if(*p != 0x90) return false;
            return true;
        }
        return false;
    };
    std::map<std::string, std::vector<Chunk *>> byObjName;
    for(auto *chunk : chunks) {
        auto it = byObjName.find(chunk->objName);
        if(it == byObjName.end()) {
            auto it2 = byObjName.insert(std::make_pair(chunk->objName, std::vector<Chunk *>()));
            it = it2.first;
        }
        if(ignoreChunk(chunk)) continue;
        // fill missing names
        if(chunk->name.empty()) {
            std::string secName = chunk->exeSecName.starts_with('.') ? chunk->exeSecName.substr(1) : chunk->exeSecName;
            std::string nameBuf;
            {
                nameBuf.resize(16);
                int len = snprintf(nameBuf.data(), nameBuf.capacity(), "%08X", chunk->va);
                nameBuf.resize(len);
            }
            chunk->name += "dk2_";
            chunk->name += secName;
            chunk->name += "_";
            chunk->name += nameBuf;
        }
        it->second.push_back(chunk);
    }
    // !!! end of obj splitting !!!

    std::string delinkedPath = delinked_dir;
    if(!delinkedPath.ends_with('/') && !delinkedPath.ends_with('\\')) delinkedPath += '/';
    for(auto &it : byObjName) {
        printf("build coff %s\n", it.first.c_str());
        std::vector<uint8_t> coff_buf;
        if(!buildCoff(it.second, coff_buf)) return -1;
        std::string path = delinkedPath + it.first;
        // skip update unchanged obj file, because it will trigger recompilation process
        if(std::filesystem::exists(path) && std::filesystem::file_size(path) == coff_buf.size()) {
            // todo: better implement with hash function
            std::vector<uint8_t> data;
            if(readBinaryFile(path, data)) {
                if(memcmp(data.data(), coff_buf.data(), coff_buf.size()) == 0) continue;
            }
        }
        if(!writeBinaryFile(path, coff_buf)) {
            printf("[-] write error %s\n", it.first.c_str());
            return -1;
        }
        std::string mapPath = path + ".map";
        {
            std::ofstream os(mapPath);
            if (!os.is_open()) {
                printf("[-] write delink mapping failed %s\n", it.first.c_str());
                return -1;
            }
            for(auto *ch : it.second) {
                os << fmtHex32(ch->va) << " " << ch->name << std::endl;
                for(auto &it2 : ch->symbols) {
                    os << "sym " << fmtHex32(ch->va + it2.first) << " " << it2.second << std::endl;
                }
            }
        }
    }
    printf("finished in %lu ms\n", GetTickCount() - startMs);
    return 0;
}
