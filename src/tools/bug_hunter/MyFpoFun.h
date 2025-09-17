//
// Created by DiaLight on 9/17/2025.
//

#ifndef FLAME_MYFPOFUN_H
#define FLAME_MYFPOFUN_H

#include <Windows.h>
#include <vector>


enum MySpdType {
    MST_Ida = 0,
    MST_Fpo = 1,
    MST_Frm = 2
};
struct MySpd {
    size_t offs;
    int spd;
    DWORD ty;
    DWORD kind;
};

struct MyFpoFun {
    DWORD rva;
    DWORD rva_end;
    const char *name;
    std::vector<MySpd> spds;


    std::vector<MySpd>::iterator find_ge(DWORD offs) {
        return std::lower_bound(spds.begin(), spds.end(), offs, [](MySpd &bl, DWORD offs) {  // <=
            return bl.offs < offs;
        });
    }
};

#endif // FLAME_MYFPOFUN_H
