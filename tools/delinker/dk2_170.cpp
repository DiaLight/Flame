//
// Created by DiaLight on 16.06.2024.
//
#include "dk2.h"
#include "chunk/Chunk.h"
#include "Global.h"
#include <Windows.h>
#include <iostream>
#include <sstream>
#include <vector>
#include "SGMap.h"


bool collectSectionChunks(uint8_t *base, std::vector<SectionChunk> &out) {
    auto *dos = (IMAGE_DOS_HEADER *) base;
    auto *nt = (IMAGE_NT_HEADERS32 *) (base + dos->e_lfanew);

    printf("\n");
    printf("parsed DKII.EXE mapping:\n");
    for(IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt), *secEnd = sec + nt->FileHeader.NumberOfSections; sec < secEnd; sec++) {
        std::string secName;
        {
            char buf[9];
            memcpy(buf, sec->Name, 8);
            buf[8] = '\0';
            secName = buf;
        }
        // DKII.EXE contains uninitialized data, but OptionalHeader.SizeOfUninitializedData == 0 and section headers has no IMAGE_SCN_CNT_UNINITIALIZED_DATA
        uint32_t chunkStart = nt->OptionalHeader.ImageBase + sec->VirtualAddress;
        uint32_t virtualEnd = chunkStart + sec->Misc.VirtualSize;
        uint32_t rawEnd = chunkStart + sec->SizeOfRawData;

        uint32_t uninitializedData = virtualEnd;
        uint32_t chunkEnd = virtualEnd;
        if(secName == ".text") {            // R-X virtualEnd=00652AA2 rawEnd=00652C00 endVal=56000400
            // ok
        } else if(secName == ".cseg") {     // R-X virtualEnd=0066BE1A rawEnd=0066C000 endVal=56000400
            // ok
        } else if(secName == ".rdata") {    // R-- virtualEnd=0068D53B rawEnd=0068D600
            uninitializedData = virtualEnd + 1;
            chunkEnd = virtualEnd + 1;
        } else if(secName == ".data") {     // RW- virtualEnd=007A6DD0 rawEnd=006CCC00
            // in dk2_170 uninitialized data starts with va=006CCA20
            uninitializedData = 0x006CCA20;
        } else if(secName == "grpoly_d") {  // RW- virtualEnd=007A7730 rawEnd=007A7800 endVal=56000400
            // ok
        } else if(secName == "uva_data") {  // RW- virtualEnd=007ACACC rawEnd=007ACC00 endVal=56000400
            // ok
        } else if(secName == "idct_dat") {  // RW- virtualEnd=007AE658 rawEnd=007AE800 endVal=56000400
            // ok
        } else if(secName == "tqia_dat") {  // RW- virtualEnd=007AFA00 rawEnd=007AFA00
            // ok
        } else if(secName == "dseg") {      // RW- virtualEnd=007B1004 rawEnd=007B1200 endVal=56000400
            // ok
        } else if(secName == "lbmpeg_d") {  // RW- virtualEnd=007B2400 rawEnd=007B2400
            // ok
        } else if(secName == ".rsrc") {     // R-- virtualEnd=007B5F2E rawEnd=007B6000 endVal=006E2D00
            uninitializedData = virtualEnd + 2;
            chunkEnd = virtualEnd + 2;
        }
        if(chunkStart != uninitializedData) {
            auto &ch = out.emplace_back();
            ch.start = chunkStart;
            ch.end = uninitializedData;
            ch.secName = secName;
            ch.chars = sec->Characteristics;
            ch.chars |= IMAGE_SCN_CNT_INITIALIZED_DATA;
            ch.chars &= ~IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            printf("%08X-%08X %s %-8s\n",
                   ch.start, ch.end,
                   format_acc(ch.chars).c_str(),
                   secName.c_str());
            ch.data.resize(uninitializedData - chunkStart);
            memcpy((char *) &ch.data.front(), base + sec->PointerToRawData, ch.end - ch.start);
        }
        if(uninitializedData != chunkEnd) {
            auto &ch = out.emplace_back();
            ch.start = uninitializedData;
            ch.end = chunkEnd;
            ch.chars = sec->Characteristics;
            ch.chars &= ~IMAGE_SCN_CNT_INITIALIZED_DATA;
            ch.chars |= IMAGE_SCN_CNT_UNINITIALIZED_DATA;
            ch.secName = secName;
            printf("%08X-%08X %s %-8s uninitialized\n",
                   ch.start, ch.end,
                   format_acc(ch.chars).c_str(),
                   secName.c_str());
            ch.data.resize(chunkEnd - uninitializedData);
            memset((char *) &ch.data.front(), 0, ch.end - ch.start);
        }
    }
    return true;
}

int findSectionIdxByAddr(std::vector<SectionChunk> &sections, uint32_t addr) {
    for (int i = 0; i < sections.size(); ++i) {
        auto &sec = sections[i];
        if(sec.start <= addr && addr < sec.end) return i;
    }
    return -1;
}
DWORD Rva2Offset(DWORD rva, IMAGE_NT_HEADERS32 *nt) {
    if(rva == 0) return rva;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for(size_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if(sec->VirtualAddress <= rva && rva < sec->VirtualAddress + sec->Misc.VirtualSize) break;
        sec++;
    }
    return rva - sec->VirtualAddress + sec->PointerToRawData;
}

bool buildChunks(std::vector<SectionChunk> &&sections, std::vector<VaReloc> &&relocs,
                 std::vector<Chunk *> &out,
                 ChunkArena &arena) {
    size_t loadedRelocs = relocs.size();

    // build chunks from sections data
    for(auto &sec : sections) {
        auto &chunk = out.emplace_back(arena.chunks.emplace_back(new Chunk()).get());
        chunk->va = sec.start;
        chunk->exeSecName = std::move(sec.secName);
        chunk->data = std::move(sec.data);
        chunk->chars = sec.chars;

        if(chunk->exeSecName.starts_with('.')) {
            chunk->objName = chunk->exeSecName.substr(1);
        } else {
            chunk->objName = chunk->exeSecName;
        }
        if(chunk->isUninitialized()) {
            chunk->objName += "_u";
        }
        chunk->objName += ".obj";

//        if(chunk->isExecute()) {
//            chunk->objSecName = ".text$mn";
//        } else if(chunk->isReadonly()) {
//            chunk->objSecName = ".rdata";
//        } else {
//            chunk->objSecName = ".data";
//            if(chunk->isUninitialized()) {
//                chunk->objSecName = ".bss";
//            }
//        }
        // rename default sections
        if(chunk->exeSecName == ".text") {
            chunk->objSecName = ".dkii";
        } else if(chunk->exeSecName == ".data") {
            if(chunk->isUninitialized()) {
                chunk->objSecName = ".dkii_u";
            } else {
                chunk->objSecName = ".dkii_d";
            }
        } else if(chunk->exeSecName == ".rdata") {
            chunk->objSecName = ".dkii_r";
        } else {
            chunk->objSecName = chunk->exeSecName;
        }
    }

    // convert absolute addresses to chunk local offsets
    for (int i = 0; i < sections.size(); ++i) {
        auto &sec = sections[i];
        auto &chunk = out[i];

        auto fr = find_ge(relocs, sec.start);
        auto to = find_ge(relocs, sec.end);
        for(auto it = fr; it < to; it++) {
            auto *ref = arena.refs.emplace_back(new ChunkRef()).get();

            switch (it->ty) {
                case VaReloc::RT_VA32:
                    ref->rel.type = IMAGE_REL_I386_DIR32;
                    break;
                case VaReloc::RT_REL32:
                    ref->rel.type = IMAGE_REL_I386_REL32;
                    break;
            }

            // convert relocs to local (va -> offs)
            ref->rel.offs = it->from - sec.start;
            ref->rel.value = it->value;
            int j = findSectionIdxByAddr(sections, it->to);
            if(j == -1) return false;
            auto &secTo = sections[j];
            auto &chunkTo = out[j];
            ref->rel.offsTo = it->to - secTo.start;
            ref->chunk = chunkTo;
            chunk->refs.push_back(ref);
        }
        relocs.erase(fr, to);
    }

    // validate all absolute relocs converted
    if(!relocs.empty()) {
        printf("[-] relocs out of bounds\n");
        return false;
    }
    // fill xrefs
    for(auto &chunk : out) {
        for(auto &ref : chunk->refs) {
            auto *xref = arena.refs.emplace_back(new ChunkRef()).get();
            xref->chunk = chunk;
            xref->rel = ref->rel;
            ref->chunk->xrefs.push_back(xref);
        }
    }
    {
        printf("\n");
        printf("parsed relocs: (count=%d)\n", loadedRelocs);
        size_t cnt = 0;
        for(auto &chunk : out) {
            cnt += chunk->refs.size();
            if(!chunk->refs.empty()) {
                printf("%08X %-8s %-8s relocs count=%d\n", chunk->va, chunk->exeSecName.c_str(), chunk->objSecName.c_str(), chunk->refs.size());
            } else {
                printf("%08X %-8s %-8s\n", chunk->va, chunk->exeSecName.c_str(), chunk->objSecName.c_str());
            }
        }
        if(loadedRelocs != cnt) {
            printf("[-] relocs leaking\n");
            return false;
        }
    }

    return true;
}

const std::map<std::string, std::map<WORD, std::string>> LibOrdinalNames = {
        {"WSOCK32.dll", {
                {116, "WSACleanup"},
                {11, "inet_ntoa"},
                {52, "gethostbyname"},
                {57, "gethostname"},
                {115, "WSAStartup"},
        }},
        {"DSOUND.dll", {
                {1, "DirectSoundCreate"},
        }}
};

bool collectImports(uint8_t *base, std::vector<Global *> &out, SGMapArena &arena) {
    auto *dos = (IMAGE_DOS_HEADER *) base;
    auto *nt = (IMAGE_NT_HEADERS32 *) (base + dos->e_lfanew);
    auto &importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if(importDir.Size != 0) {
//        printf("parsed imports:\n");
        for(
                auto *desc = (IMAGE_IMPORT_DESCRIPTOR *) (base + Rva2Offset(importDir.VirtualAddress, nt));
                desc->OriginalFirstThunk != NULL; desc++) {
            char *libname = (char *) (base + Rva2Offset(desc->Name, nt));
//            printf("%s\n", libname);
            const std::map<WORD, std::string> *OrdinalNames = nullptr;
            {
                auto it = LibOrdinalNames.find(libname);
                if(it != LibOrdinalNames.end()) {
                    OrdinalNames = &it->second;
                }
            }
            auto *lookups = (IMAGE_THUNK_DATA *) (base + Rva2Offset(desc->OriginalFirstThunk, nt));
            auto *addressesBase = (IMAGE_THUNK_DATA *) (base + Rva2Offset(desc->FirstThunk, nt));
            auto *addresses = addressesBase;
            for (; lookups->u1.AddressOfData != 0; lookups++, addresses++) {
                uint32_t rva = desc->FirstThunk + ((uintptr_t) &addresses->u1.Function - (uintptr_t) addressesBase);
                uint32_t va = nt->OptionalHeader.ImageBase + rva;
                WORD hint;
                std::string name;
                if ((lookups->u1.AddressOfData & IMAGE_ORDINAL_FLAG) != 0) {
                    if (OrdinalNames != nullptr) {
                        auto it = OrdinalNames->find((WORD) lookups->u1.AddressOfData);
                        if(it != OrdinalNames->end()) {
                            name = it->second;
                        }
                    }
                    if(name.empty()) {
                        printf("[-] name for ordinal not found\n");
                        return false;
                    }
                    hint = (WORD) lookups->u1.AddressOfData;
                } else {
                    auto *byName = (IMAGE_IMPORT_BY_NAME *) (base + Rva2Offset(lookups->u1.AddressOfData, nt));
                    hint = byName->Hint;
                    name = byName->Name;
                }
//                printf("  %08X %d %s\n", va, hint, name.c_str());
                auto *global = out.emplace_back(arena.globals.emplace_back(new Global(va, name)).get());
                global->size = 4;
            }
        }
    }
    return true;
}
