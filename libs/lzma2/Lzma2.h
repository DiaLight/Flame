//
// Created by DiaLight on 10/5/2025.
//

#ifndef FLAME_LZMA2_H
#define FLAME_LZMA2_H

#include <vector>
#include <span>
#include <functional>

std::vector<std::byte> lzma2_encode(std::span<const std::byte> data);
std::vector<std::byte> lzma2_decode(std::span<const std::byte> data, const std::function<void(int cur, int max)> &progress);


#endif // FLAME_LZMA2_H
