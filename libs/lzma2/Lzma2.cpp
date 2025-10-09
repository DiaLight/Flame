//
// Created by DiaLight on 10/5/2025.
//

#include "Lzma2.h"
#include <Windows.h>
#include <memory>
#include <vector>
#include "7zTypes.h"
#include "Lzma2Dec.h"
#include "Lzma2Enc.h"


#define ALLOC_ALIGN_SIZE ((size_t)1 << 7)
static void *SzAlignedAlloc(ISzAllocPtr pp, size_t size) {
    return _aligned_malloc(size, ALLOC_ALIGN_SIZE);
}
static void SzAlignedFree(ISzAllocPtr pp, void *address) {
    if (address) _aligned_free(address);
}
static void *SzBigAlloc(ISzAllocPtr p, size_t size) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size); }
static void SzBigFree(ISzAllocPtr p, void *address) { HeapFree(GetProcessHeap(), 0, address); }
const ISzAlloc g_BigAlloc = { SzBigAlloc, SzBigFree };
const ISzAlloc g_AlignedAlloc = { SzAlignedAlloc, SzAlignedFree };

std::vector<std::byte> lzma2_encode(std::span<const std::byte> data) {
    size_t outSize = (int)(1.001 * data.size() + 1000);
    std::vector<std::byte> out;
    out.resize( 1 + outSize);  // reserve
    Byte *o = (Byte *) out.data();
    SRes res;
    {
        auto *_encoder = Lzma2Enc_Create(&g_AlignedAlloc, &g_BigAlloc);
        res = Lzma2Enc_Encode2(
            _encoder,
            NULL, o + 1, &outSize,
            NULL, (const Byte*) data.data(), data.size(),
            NULL);
        Byte prop = Lzma2Enc_WriteProperties(_encoder);
        Lzma2Enc_Destroy(_encoder);
        o[0] = prop;
    }
    out.resize(1 + outSize);  // shrink
    if(res != SZ_OK) {
        printf("Lzma2Enc_Encode2 failed with res=%d\n", res);
        return {};
    }
    return out;
}

struct Lzma2DecStateCxx : CLzma2Dec {

    Lzma2DecStateCxx() : CLzma2Dec() {
        Lzma2Dec_Construct(this);
        Lzma2Dec_Init(this);
    }
    ~Lzma2DecStateCxx() {
        Lzma2Dec_Free(this, &g_BigAlloc);
    }
};

std::vector<std::byte> lzma2_decode(std::span<const std::byte> data) {
    Byte *d = (Byte *) data.data();
    Byte *e = d + data.size();

    Lzma2DecStateCxx _state;
    SRes res = Lzma2Dec_Allocate(&_state, *d++, &g_BigAlloc);
    if(res != SZ_OK) {
        printf("Lzma2Dec_Allocate failed with res=%d\n", res);
        return {};
    }

    static const UInt32 kInBufSize = 1 << 20;  // 1MB

    std::vector<std::byte> out;
    UInt64 outOffs = 0;
    while(d < e) {
        out.resize(outOffs + kInBufSize);  // extend
        SizeT inProcessed = e - d;
        SizeT outProcessed = kInBufSize;
        ELzmaStatus status;
        res = Lzma2Dec_DecodeToBuf(
            &_state, (Byte*) out.data() + outOffs, &outProcessed,
            d, &inProcessed,
            LZMA_FINISH_ANY, &status);
        d += inProcessed;
        outOffs += outProcessed;
        out.resize(outOffs);  // shrink
        if(res != SZ_OK) {
            printf("Lzma2Dec_DecodeToBuf failed with res=%d\n", res);
            return {};
        }
        if (inProcessed == 0 && outProcessed == 0) {
            printf("there still compressed data, but lzma2 tells end of compression\n");
            return {};
        }
//        printf("step %d\n", out.size());
    }
    return out;
}
