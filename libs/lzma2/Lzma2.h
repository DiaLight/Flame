//
// Created by DiaLight on 10/5/2025.
//

#ifndef FLAME_LZMA2_H
#define FLAME_LZMA2_H

#include <vector>
#include <span>

std::vector<std::byte> lzma2_encode(std::span<const std::byte> data);
std::vector<std::byte> lzma2_decode(std::span<const std::byte> data);


#endif // FLAME_LZMA2_H
