//
// Created by DiaLight on 10.01.2025.
//

#ifndef FLAME_DK2_MEMORY_H
#define FLAME_DK2_MEMORY_H

#include <utility>

namespace dk2 {

    void *call_malloc(size_t size);

    void call_free(void *buf);

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

    template<typename T, bool empty_destructor = false>
    void for_each_construct(
            void *buf,
            int count) {
        uint8_t *pos = (uint8_t *) buf;
        bool success = false;
        int i = 0;
        __try{
            for (; i < count; ++i ) {
                ((T *) pos)->constructor();
                pos += sizeof(T);
            }
            success = true;
        } __finally {
            if(!success) {
                if constexpr(!empty_destructor) {
                    while(--i > 0) {
                        pos -= sizeof(T);
                        ((T *) pos)->destructor();
                    }
                }
            }
        }
    }

    template<typename T, bool empty_destructor = false>
    void for_each_destruct(void *buf, int count) {
        if constexpr(!empty_destructor) {
            uint8_t *pos = (uint8_t *) buf + count * sizeof(T);
            while (--count >= 0) {
                pos -= sizeof(T);
                ((T *) pos)->destructor();
            }
        }
    }

    template<typename T>
    void for_each_construct_(
            void *buf,
            int count) {
        uint8_t *pos = (uint8_t *) buf;
        bool success = false;
        int i = 0;
        __try{
            for (; i < count; ++i ) {
                new (pos) T();
                pos = pos + sizeof(T);
            }
            success = true;
        } __finally {
            if(!success) {
                while(--i > 0) {
                    pos -= sizeof(T);
                    ((T *) pos)->~T();
                }
            }
        }
    }

}

#endif //FLAME_DK2_MEMORY_H
