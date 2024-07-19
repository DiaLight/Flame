//
// Created by DiaLight on 18.06.2024.
//

#include "CoffBuilder.h"
#include <Windows.h>
#include <map>
#include <string>
#include <cassert>


void writeBuf(std::vector<uint8_t> &buf, const void *p, size_t s) {
    if(s == 0) return;
    size_t offs = buf.size();
    buf.resize(offs + s);
    memcpy(&buf[offs], p, s);
}

struct SECTION {
    IMAGE_SECTION_HEADER header;
    SHORT Number = 0;
    BYTE Selection = 0;
    Chunk *chunk;
    std::vector<IMAGE_RELOCATION> relocations;
};


class CoffBuilder {
    // https://coffi.readthedocs.io/en/latest/pecoff_v11.pdf
    // https://www.openwatcom.org/ftp/devel/docs/CodeView.pdf

    IMAGE_FILE_HEADER header;
    std::map<Chunk *, uint32_t> sections_map;
    std::vector<std::shared_ptr<SECTION>> sections;  // std::shared_ptr because i dont want complex data move on vector grow
    static_assert(sizeof(IMAGE_SYMBOL) == sizeof(IMAGE_AUX_SYMBOL));
    std::map<std::string, size_t> used_external_symbols;
    std::vector<IMAGE_SYMBOL> symbols;  // warning: here can be IMAGE_SYMBOL or IMAGE_AUX_SYMBOL structures mixed together
    std::map<std::string, size_t> used_strings;
    std::vector<uint8_t> strings;
    Chunk _drectveChunk;
    std::vector<std::unique_ptr<Chunk>> _comdats;
    std::vector<std::unique_ptr<ChunkRef>> _comdatRefs;

public:
    CoffBuilder() : header() {
        _drectveChunk.objSecName = ".drectve";
        _drectveChunk.chars = IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_ALIGN_1BYTES;
        std::string directive = R"(   /DEFAULTLIB:"uuid.lib" /DEFAULTLIB:"LIBCMT" /DEFAULTLIB:"OLDNAMES" )";
        writeBuf(_drectveChunk.data, directive.data(), directive.size());
        add(&_drectveChunk);
    }

    void genComdat(Chunk *chunk, uint32_t secNum);
    void add(Chunk *chunk);

    [[nodiscard]] bool layout(size_t &totalSize);

    void build(std::vector<uint8_t> &buf);

    uint32_t addString(const std::string &name) {
        auto it = used_strings.find(name);
        if(it != used_strings.end()) return it->second;
        uint32_t offs = strings.size();
        strings.resize(strings.size() + name.size());
        memcpy(&strings[offs], name.data(), name.size());
        strings.push_back('\0');
        offs += 4;
        used_strings.insert(std::make_pair(name, offs));
        return offs;
    }
    void setNameField(BYTE *field, const std::string &name) {
        ZeroMemory(field, 8);
        if(name.size() <= 8) {
            memcpy(field, name.data(), name.size());
        } else {
            auto *intFld = (LARGE_INTEGER *) field;
            intFld->LowPart = 0;
            intFld->HighPart = (LONG) addString(name);
        }
    }

    std::string formatSymbol(Chunk *chunk, uint32_t offs, bool &isLocalLabel) {
        std::string name = chunk->name;
        assert(!name.empty());
        if(offs != 0) {
            // try find symbol to offs
            auto it = chunk->symbols.find(offs);
            if(it != chunk->symbols.end()) {
                name = it->second;
                isLocalLabel = false;
            } else {
                char nameBuf[16];
                snprintf(nameBuf, sizeof(nameBuf), "_%X", offs);
                name += nameBuf;
            }
        }
        if(isLocalLabel) name = "$" + name;  // make it label
        return name;
    }
    uint32_t getSymbolId(Chunk *chunk, uint32_t offs, bool isLocalLabel) {
        std::string name = formatSymbol(chunk, offs, isLocalLabel);
        return getSymbolId(chunk, offs, name, isLocalLabel);
    }
    uint32_t getSymbolId(Chunk *chunk, uint32_t offs, const std::string &name, bool isLocalLabel) {
        uint32_t sectionNumber = 0;
        {
            auto it = sections_map.find(chunk);
            if(it != sections_map.end()) {
                sectionNumber = it->second;
            }
        }
        if(sectionNumber == 0) {
            // if chunk not belongs to this obj file, then symbol has no offs
            offs = 0;
        }
        auto it = used_external_symbols.find(name);
        if(it != used_external_symbols.end()) return it->second;
        size_t symId = symbols.size();
        auto &sym = symbols.emplace_back();
        setNameField(sym.N.ShortName, name);
        sym.Value = offs;
        sym.SectionNumber = sectionNumber;
        if(chunk->isExecute()) {
            sym.Type = (IMAGE_SYM_DTYPE_FUNCTION << 4) | IMAGE_SYM_TYPE_NULL;
        } else {
            sym.Type = (IMAGE_SYM_DTYPE_NULL << 4) | IMAGE_SYM_TYPE_NULL;
        }
        if(isLocalLabel) {
            sym.StorageClass = IMAGE_SYM_CLASS_LABEL;
        } else {
            sym.StorageClass = IMAGE_SYM_CLASS_EXTERNAL;
        }
        sym.NumberOfAuxSymbols = 0;
        used_external_symbols.insert(std::make_pair(name, symId));
        return symId;
    }

    uint32_t createSymbol(std::shared_ptr<SECTION> &sec) {
        uint32_t sectionNumber = -1;
        {
            auto it = sections_map.find(sec->chunk);
            if(it != sections_map.end()) {
                sectionNumber = it->second;
            }
        }
        if(sectionNumber == -1) {
            if(sec->chunk == &_drectveChunk) {
                sectionNumber = 1;
            }
        }
        assert(sectionNumber != -1);
        size_t symId = symbols.size();
        auto &sym = symbols.emplace_back();
        {
//            std::string name = sec->chunk->secName;
//            setNameField(sym.N.ShortName, name);
            memcpy(sym.N.ShortName, sec->header.Name, 8);
        }
        sym.Value = 0;
        sym.SectionNumber = sectionNumber;
//        if(chunk->isExecute()) {
//            sym.Type = (IMAGE_SYM_DTYPE_FUNCTION << 4) | IMAGE_SYM_TYPE_NULL;
//        } else {
//        }
        sym.Type = (IMAGE_SYM_DTYPE_NULL << 4) | IMAGE_SYM_TYPE_NULL;
        sym.StorageClass = IMAGE_SYM_CLASS_STATIC;
        sym.NumberOfAuxSymbols = 1;
        auto &aux = *(IMAGE_AUX_SYMBOL *) &symbols.emplace_back();
        aux.Section.Length = sec->chunk->data.size();
        aux.Section.NumberOfRelocations = sec->chunk->refs.size();
        aux.Section.NumberOfLinenumbers = 0;
        aux.Section.CheckSum = 0;  // can be 0
        aux.Section.Number = sec->Number;
        aux.Section.Selection = sec->Selection;
        aux.Section.bReserved = 0;
        aux.Section.HighNumber = 0;
        return symId;
    }

};

void CoffBuilder::genComdat(Chunk *chunk, uint32_t secNum) {
    auto *comdat = _comdats.emplace_back(new Chunk()).get();
    static_assert(sizeof(FPO_DATA) == 0x10);
    comdat->data.resize(sizeof(FPO_DATA));
    FPO_DATA &fpoData = *(FPO_DATA *) comdat->data.data();
    fpoData.cbProcSize = chunk->data.size();
    {
        auto *ref = _comdatRefs.emplace_back(new ChunkRef()).get();
        ref->chunk = chunk;
        ref->rel.offs = 0;
        ref->rel.value = 0;
        ref->rel.type = IMAGE_REL_I386_DIR32NB;
        ref->rel.offsTo = 0;
        comdat->refs.push_back(ref);
    }

    auto &sec = sections.emplace_back(new SECTION());
    sections_map.insert(std::make_pair(comdat, sections.size()));
    setNameField(sec->header.Name, ".debug$F");
    sec->header.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_LNK_COMDAT | IMAGE_SCN_ALIGN_1BYTES | IMAGE_SCN_MEM_DISCARDABLE | IMAGE_SCN_MEM_READ;
    sec->chunk = comdat;
    sec->Selection = IMAGE_COMDAT_SELECT_ASSOCIATIVE;
    sec->Number = secNum;
}
void CoffBuilder::add(Chunk *chunk) {
    auto &sec = sections.emplace_back(new SECTION());
    uint32_t secNum = sections.size();
    sections_map.insert(std::make_pair(chunk, secNum));
    setNameField(sec->header.Name, chunk->objSecName);
    sec->header.Characteristics = chunk->chars;
    if(chunk->isExecute()) {
        sec->header.Characteristics &= ~IMAGE_SCN_CNT_INITIALIZED_DATA;
        sec->header.Characteristics |= IMAGE_SCN_ALIGN_1BYTES;
//        sec->header.Characteristics |= IMAGE_SCN_LNK_COMDAT;
    } else {
        sec->header.Characteristics |= IMAGE_SCN_ALIGN_8BYTES;
    }
    sec->chunk = chunk;
    // have no idea what is this, but trying to mimic msvc behaviour
    if(sec->chunk->isExecute()) {
        sec->Selection = IMAGE_COMDAT_SELECT_NODUPLICATES;
    } else if(sec->chunk->isReadonly()) {
        sec->Selection = IMAGE_COMDAT_SELECT_ANY;
    } else {
        sec->Selection = 0;
    }
    if(chunk->isExecute()) {
//        genComdat(chunk, secNum);
    }
}

bool CoffBuilder::layout(size_t &totalSize) {
    if(sections.size() > 0xFFFF) {
        printf("[-] too many sections 0x%X\n", sections.size());
        return false;
    }
    size_t offs = 0;

    header.Machine = IMAGE_FILE_MACHINE_I386;
    header.NumberOfSections = sections.size();
    header.TimeDateStamp = 0;  // todo: build timestamp

//    header.PointerToSymbolTable = 0;
//    header.NumberOfSymbols = 0;

    header.SizeOfOptionalHeader = 0;
    header.Characteristics = 0;

    offs += sizeof(header);
    offs += sections.size() * sizeof(IMAGE_SECTION_HEADER);
    for(auto &sec : sections) {
        createSymbol(sec);
        if(!sec->chunk->name.empty()) {
            getSymbolId(sec->chunk, 0, false);  // force define section name
        }
        for(auto &it : sec->chunk->symbols) {  // links to defined symbols
            getSymbolId(sec->chunk, it.first, it.second, false);
        }
        for(auto *chunk_xref : sec->chunk->xrefs) {  // links from others symbols
            if(sec->chunk != chunk_xref->chunk) {
                getSymbolId(sec->chunk, chunk_xref->rel.offsTo, chunk_xref->chunk->isJumpTable);
            }
        }
        for(auto *chunk_ref : sec->chunk->refs) {  // links to potential undefined symbols
            auto &rel = sec->relocations.emplace_back();
            rel.VirtualAddress = chunk_ref->rel.offs;
            // create external symbol
            bool isSelfRef = sec->chunk == chunk_ref->chunk;
            bool isLocalLabel = isSelfRef || sec->chunk->isJumpTable;
            std::string name = formatSymbol(chunk_ref->chunk, chunk_ref->rel.offsTo, isLocalLabel);
            if(isLocalLabel) {  // in case of local label ref
                if(!sec->chunk->isExcluded && chunk_ref->chunk->isExcluded) {
                    printf("[-] there chunk 0x%X %s+0x%X local refers to replaced chunk %s+0x%X\n",
                           sec->chunk->va, sec->chunk->name.c_str(), chunk_ref->rel.offs,
                           chunk_ref->chunk->name.c_str(), chunk_ref->rel.offsTo);
                    return false;
                }
            }
            rel.SymbolTableIndex = getSymbolId(chunk_ref->chunk, chunk_ref->rel.offsTo, name, isLocalLabel);
            *(uint32_t *) (sec->chunk->data.data() + chunk_ref->rel.offs) = chunk_ref->rel.value;
            rel.Type = chunk_ref->rel.type;
        }
    }
    for(auto &sec : sections) {
//        sec->header.Name = ;
        sec->header.Misc.VirtualSize = 0;
        sec->header.VirtualAddress = 0;
        sec->header.SizeOfRawData = sec->chunk->data.size();
        if(sec->chunk->isUninitialized()) {
            sec->header.PointerToRawData = 0;
            sec->header.PointerToRelocations = 0;
            assert(sec->relocations.empty());
        } else {
            sec->header.PointerToRawData = offs;
            offs += sec->chunk->data.size();
            sec->header.PointerToRelocations = offs;
            offs += sec->relocations.size() * sizeof(sec->relocations[0]);
        }
        sec->header.PointerToLinenumbers = 0;
        if(sec->relocations.size() > 0xFFFF) {
            printf("[-] too many relocations 0x%X for %s\n", sec->relocations.size(), sec->chunk->name.c_str());
            return false;
        }
        sec->header.NumberOfRelocations = sec->relocations.size();
//        sec->header.Characteristics = ;
    }

    header.NumberOfSymbols = symbols.size();
    header.PointerToSymbolTable = symbols.empty() ? 0 : offs;

    offs += symbols.size() * sizeof(symbols[0]);
    offs += strings.size();
    totalSize = offs;
    return true;
}

void CoffBuilder::build(std::vector<uint8_t> &buf) {
    writeBuf(buf, &header, sizeof(header));
    // section headers
    for(auto &sec : sections) {
        writeBuf(buf, &sec->header, sizeof(sec->header));
    }
    // section data and relocs
    for(auto &sec : sections) {
        if(sec->chunk->isUninitialized()) continue;
        writeBuf(buf, sec->chunk->data.data(), sec->chunk->data.size());
        writeBuf(buf, sec->relocations.data(), sec->relocations.size() * sizeof(sec->relocations[0]));
    }
    // symbols
    writeBuf(buf, symbols.data(), symbols.size() * sizeof(symbols[0]));
    // strings
    uint32_t stringsSize = strings.size() + 4;
    writeBuf(buf, &stringsSize, sizeof(stringsSize));
    writeBuf(buf, strings.data(), strings.size());
}


bool buildCoff(std::vector<Chunk *> &chunks, std::vector<uint8_t> &buf) {
    CoffBuilder builder;
    // prepare
    for(auto &chunk : chunks) builder.add(chunk);
    // layout
    size_t totalSize;
    if(!builder.layout(totalSize)) return false;
    buf.reserve(totalSize);
    // bake
    builder.build(buf);
    return true;
}
