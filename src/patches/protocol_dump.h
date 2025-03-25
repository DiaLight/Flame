//
// Created by DiaLight on 11.03.2025.
//

#ifndef FLAME_PROTOCOL_DUMP_H
#define FLAME_PROTOCOL_DUMP_H


namespace patch::protocol_dump {

    void tick();
    void onSend(size_t srcSlot, size_t dstSlot, void *data, size_t size, bool guaranteed);
    void onRecv(size_t srcSlot, size_t dstSlot, void *data, size_t size, const char *group);
    void onRecvGuaranteed(size_t srcSlot, size_t dstSlot, void *data, size_t size);

    void init();

};


#endif //FLAME_PROTOCOL_DUMP_H
