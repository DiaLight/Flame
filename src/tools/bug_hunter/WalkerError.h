//
// Created by DiaLight on 9/17/2025.
//

#ifndef FLAME_WALKERERROR_H
#define FLAME_WALKERERROR_H

#include <string>

class WalkerError {
    std::string error;
public:
    WalkerError() = default;

    inline bool operator ! () const { return error.empty(); }
    inline explicit operator bool() const { return !error.empty(); }

    std::string str() { return error; }
    const char *c_str() { return error.c_str(); }

private:
    friend struct StackWalkerState;
    void set(const char *err) { this->error = err; }
    void set(const std::string &err) { this->error = err; }

};


#endif // FLAME_WALKERERROR_H
