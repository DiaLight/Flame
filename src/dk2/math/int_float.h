//
// Created by DiaLight on 5/17/2025.
//

#ifndef INT_FLOAT_H
#define INT_FLOAT_H

#include "dk2/IntFloat12.h"


// inf as float with 12 bit precision math

namespace dk2ex {

    dk2::IntFloat12 IFl12_from(uint32_t value);
    inline dk2::IntFloat12 IFl12_from(DWORD value) {return IFl12_from((uint32_t) value); }

    dk2::IntFloat12 IFl12_from(float value);

    float toFloat(dk2::IntFloat12 &value);

}



#endif //INT_FLOAT_H
