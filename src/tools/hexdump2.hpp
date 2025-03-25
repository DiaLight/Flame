//
// Created by DiaLight on 18.01.2025.
//

#ifndef FLAME_HEXDUMP_HPP
#define FLAME_HEXDUMP_HPP

#include <iostream>
#include <iomanip>

#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec

static void hexdump(std::ostream &os, const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        os << fmtHex8(((unsigned char*)data)[i]) << " ";
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            os << " ";
            if ((i+1) % 16 == 0) {
                os << "|  " << ascii << " \n";
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    os << " ";
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    os << "   ";
                }
                os << "|  " << ascii << " \n";
            }
        }
    }
}

#endif //FLAME_HEXDUMP_HPP
