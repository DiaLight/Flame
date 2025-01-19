//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_PATCH_LOGGING_H
#define FLAME_PATCH_LOGGING_H


namespace patch::log {

    void dbg(const char *format, ...);

    void spmsg(const char *format, ...);

    void sock(const char *format, ...);

    void gdata(const char *format, ...);

    void err(const char *format, ...);

}


#endif //FLAME_PATCH_LOGGING_H
