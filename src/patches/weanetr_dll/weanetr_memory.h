//
// Created by DiaLight on 10.01.2025.
//

#ifndef FLAME_WEANETR_MEMORY_H
#define FLAME_WEANETR_MEMORY_H

#include <utility>

namespace net {

    void *_malloc(size_t size);

    void _free(void *buf);

    void *operator_new(size_t size);

    void operator_delete(void *buf);

    template<typename T, typename ...Args>
    T *call_new(Args&&... args) {
        void *buf = operator_new(sizeof(T));
        return new (buf) T(std::forward<Args>(args)...);
    }

    template<typename T>
    void call_delete(T *obj) {
        obj->~T();
        operator_delete(obj);
    }


}

#endif //FLAME_WEANETR_MEMORY_H
