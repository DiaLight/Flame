//
// Created by DiaLight on 15.06.2024.
//

#include "Chunk.h"
#include <Windows.h>
#include <cassert>

std::string format_acc(uint32_t chars) {
    std::string val;
    val.push_back(chars & IMAGE_SCN_MEM_READ ? 'R' : '-');
    val.push_back(chars & IMAGE_SCN_MEM_WRITE ? 'W' : '-');
    val.push_back(chars & IMAGE_SCN_MEM_EXECUTE ? 'X' : '-');
    return val;
}

bool Chunk::isUninitialized() const {
    return (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;
}

bool Chunk::isReadonly() const {
    return (chars & IMAGE_SCN_MEM_READ) != 0 && (chars & IMAGE_SCN_MEM_WRITE) == 0 && (chars & IMAGE_SCN_MEM_EXECUTE) == 0;
}

bool Chunk::isReadWrite() const {
    return (chars & IMAGE_SCN_MEM_READ) != 0 && (chars & IMAGE_SCN_MEM_WRITE) != 0 && (chars & IMAGE_SCN_MEM_EXECUTE) == 0;
}

bool Chunk::isExecute() const {
    return (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
}

ChunkRef *findByRelOffs(std::vector<ChunkRef *> &vec, Chunk *chunk, size_t offs) {
    for(auto &ref : vec) {
        if(ref->rel.offs == offs && ref->chunk == chunk) return ref;
    }
    return nullptr;
}

Chunk *Chunk::split(int offs, ChunkArena &arena) {
    if(offs <= 0) return {};
    if(offs >= data.size()) return {};

    auto *rhs = arena.chunks.emplace_back(new Chunk()).get();
    rhs->va = va + offs;
    rhs->name = name;
    rhs->exeSecName = exeSecName;
    rhs->objSecName = objSecName;
    rhs->objName = objName;
    rhs->chars = chars;

    // split data
    rhs->data.resize(data.size() - offs);  // alloc rhs
    memcpy(rhs->data.data(), &data[offs], data.size() - offs);  // copy lhs -> rhs
    data.resize(offs);  // shrink lhs
    data.shrink_to_fit();

    // collect
    std::vector<ChunkRef *> lhs_refs;
    lhs_refs.reserve(refs.size());
    std::vector<ChunkRef *> to_patch_xrefs;
    to_patch_xrefs.reserve(refs.size());
    for(auto &ref : refs) {
        if(ref->rel.offs < offs) {
            lhs_refs.push_back(ref);
        } else {
            auto xref = findByRelOffs(ref->chunk->xrefs, this, ref->rel.offs);
            assert(xref);
            to_patch_xrefs.push_back(xref);
            rhs->refs.push_back(ref);
        }
    }
    std::vector<ChunkRef *> lhs_xrefs;
    lhs_xrefs.reserve(xrefs.size());
    std::vector<ChunkRef *> to_patch_refs;
    to_patch_refs.reserve(xrefs.size());
    for(auto &xref : xrefs) {
        if(xref->rel.offsTo < offs) {
            lhs_xrefs.push_back(xref);
        } else {
            auto ref = findByRelOffs(xref->chunk->refs, this, xref->rel.offs);
            assert(ref);
            to_patch_refs.push_back(ref);
            rhs->xrefs.push_back(xref);
        }
    }
    // mutate
    for(auto *ref : rhs->refs) {
        ref->rel.offs -= offs;
    }
    for(auto *xref : rhs->xrefs) {
        xref->rel.offsTo -= offs;
    }
    for(auto *xref : to_patch_xrefs) {
        xref->rel.offs -= offs;
        xref->chunk = rhs;
    }
    for(auto *ref : to_patch_refs) {
        ref->rel.offsTo -= offs;
        ref->chunk = rhs;
    }
    refs = std::move(lhs_refs);
    xrefs = std::move(lhs_xrefs);
    refs.shrink_to_fit();
    xrefs.shrink_to_fit();
    return rhs;
}
