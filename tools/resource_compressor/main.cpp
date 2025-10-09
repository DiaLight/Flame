//
// Created by DiaLight on 9/3/2025.
//

#include <Windows.h>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "Lzma2.h"
#include "Fpo.h"

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

struct StoredResource {
    std::string_view mName;
    std::size_t mOffset {};
    std::size_t mSize {};
};

struct StoredResources {
    std::vector<std::byte> mPacked;
    std::vector<StoredResource> mResources;
    std::size_t mUncompressedBufferSize {};
};

struct InputResource {
    std::string_view mKey;
    std::span<std::byte> mData;
};

StoredResources compress(const std::span<InputResource> input) {
    StoredResources result;
    std::vector<std::byte> inputBlob;
    result.mUncompressedBufferSize = std::ranges::fold_left(input, 0, [](auto acc, const auto& resource) {
        return acc + sizeof(uint16_t) + resource.mKey.size() + sizeof(uint32_t) + resource.mData.size();
    });
    inputBlob.reserve(result.mUncompressedBufferSize);
    for (auto&& resource: input) {
        result.mResources.emplace_back(resource.mKey, inputBlob.size(), resource.mData.size());

        uint16_t keySize = resource.mKey.size();
        inputBlob.append_range(std::span{(std::byte *) &keySize, sizeof(keySize)});
        inputBlob.append_range(std::span{(std::byte *) resource.mKey.data(), resource.mKey.size()});

        uint32_t size = resource.mData.size();
        inputBlob.append_range(std::span{(std::byte *) &size, sizeof(size)});
        inputBlob.append_range(resource.mData);
    }
    result.mPacked = inputBlob;
    return result;
}

std::vector<std::byte> get_contents(const std::string &path) {
    if(std::ifstream f { path, std::ios::binary }; f) {
        auto length { std::filesystem::file_size(path) };
        std::vector<std::byte> result(length);
        f.read(
            reinterpret_cast<char*>(result.data()),
            static_cast<long>(length)
        );
        return result;
    }
    std::cerr << "Unable to correctly open file " << path <<"." << std::endl;
    return {};
}


void write_varint(std::vector<std::byte> &f, size_t number) {
    do {
        uint8_t data = number & 0x7f;
        number >>= 7;
        if(number) data |= 0x80;
        f.push_back(std::byte(data)); // put data
    } while(number);
}

void write_signed_varint(std::vector<std::byte> &f, int number) {
    if(number < 0) {
        number = ((-number) << 1) | 1;
    } else {
        number = (number << 1) | 0;
    }
    write_varint(f, number);
}

std::vector<std::byte> buildBinFpo(std::vector<FpoFun> &fpomap) {
    std::vector<std::byte> f;
    write_varint(f, fpomap.size());
    uint32_t last_va = 0;
    for (const auto& fpo : fpomap) {
        write_varint(f, fpo.va - last_va);
        write_varint(f, fpo.size);
        f.append_range(std::span{(std::byte *) fpo.name.data(), fpo.name.size()});
        f.push_back(std::byte('\0'));
        write_varint(f, fpo.spds.size());
        for (const auto& spd : fpo.spds) {
            write_varint(f, spd.offs);
            write_signed_varint(f, spd.spd);
            write_varint(f, spd.ty);
            write_varint(f, spd.kind);
        }
        last_va = fpo.va;
    }
    return f;
}

void show_help() {
    printf("resource_compressor\n");
    printf("  -symmap_file <path>\n");
    printf("  -refmap_file <path>\n");
    printf("  -dkii_fpobin_file <path>\n");
    printf("  -flame_fpobin_file <path>\n");
    printf("  -res_file <path>\n");
    printf("  -version <str>\n");
}

int main(int argc, char** argv) {
    if (hasCmdOption(argv, argv + argc, "-h")) {
        show_help();
        return EXIT_SUCCESS;
    }

    char *symmap_file = getCmdOption(argv, argv + argc, "-symmap_file");
    if (symmap_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *refmap_file = getCmdOption(argv, argv + argc, "-refmap_file");
    if (refmap_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *dkii_fpobin_file = getCmdOption(argv, argv + argc, "-dkii_fpobin_file");
    if (dkii_fpobin_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *flame_fpobin_file = getCmdOption(argv, argv + argc, "-flame_fpobin_file");
    if (flame_fpobin_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *res_file = getCmdOption(argv, argv + argc, "-res_file");
    if (res_file == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    char *version = getCmdOption(argv, argv + argc, "-version");
    if (version == nullptr) {
        show_help();
        return EXIT_FAILURE;
    }

    std::vector<std::byte> symmap = get_contents(symmap_file);
    if(symmap.empty()) return EXIT_FAILURE;
    std::vector<std::byte> refmap = get_contents(refmap_file);
    if(refmap.empty()) return EXIT_FAILURE;
    std::vector<std::byte> dkiiFpoBin = get_contents(dkii_fpobin_file);
    if(dkiiFpoBin.empty()) return EXIT_FAILURE;
    std::vector<std::byte> flameFpoBin = get_contents(flame_fpobin_file);
    if(flameFpoBin.empty()) return EXIT_FAILURE;

    InputResource resources[] {
        {"symmap", {(std::byte *) symmap.data(), symmap.size()}},
        {"refmap", {(std::byte *) refmap.data(), refmap.size()}},
        {"dkii_fpo", {(std::byte *) dkiiFpoBin.data(), dkiiFpoBin.size()}},
        {"flame_fpo", {(std::byte *) flameFpoBin.data(), flameFpoBin.size()}},
        {"version", {(std::byte *) version, strlen(version)}},
    };

    StoredResources sr = compress(resources);
    auto compressed = lzma2_encode(sr.mPacked);
    if(compressed.empty()) {
        std::cerr << "failed to Compress" << std::endl;
        return EXIT_FAILURE;
    }
    printf("uncompressed: %d\n", sr.mUncompressedBufferSize);
    printf("compressed: %d (100%% -> %.1f%%)\n", compressed.size(), compressed.size() * 100.0 / sr.mUncompressedBufferSize);
//    {  // decompress test
//        auto decTest = lzma2_decode(compressed);
//        if(decTest.empty()) {
//            std::cerr << "failed to Decompress test" << std::endl;
//            return EXIT_FAILURE;
//        }
//        printf("decompressed: %d\n", decTest.size());
//        if(decTest != sr.mPacked) {
//            std::cerr << "failed to Decompress compare" << std::endl;
//            return EXIT_FAILURE;
//        }
//    }

    {
        std::ofstream f{ res_file, std::ios::binary };
        if(!f) {
            std::cerr << "failed open res file" << std::endl;
            return EXIT_FAILURE;
        }
        f.write((const char *) compressed.data(), compressed.size());
    }

    return EXIT_SUCCESS;
}

