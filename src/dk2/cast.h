//
// Created by DiaLight on 08.08.2024.
//

#ifndef FLAME_CAST_H
#define FLAME_CAST_H


template<class T, class V>
T *dyn_cast(V *cls) {
    if(cls->getVtbl() == T::vftable) return (T *) cls;
    return nullptr;
}

#endif //FLAME_CAST_H
