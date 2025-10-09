

# https://www.7-zip.org/sdk.html
add_library(lzma2 STATIC
        lzma2501/C/Lzma2Enc.c
        lzma2501/C/LzmaEnc.c
        lzma2501/C/Lzma2Dec.c
        lzma2501/C/LzmaDec.c
        lzma2501/C/LzFind.c
        lzma2501/C/7zStream.c
        lzma2501/C/CpuArch.c
        Lzma2.cpp
)
target_include_directories(lzma2 PUBLIC lzma2501/C ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(lzma2 PUBLIC Z7_ST=1)
