//
// Created by DiaLight on 4/11/2025.
//

#ifndef REGISTRY_TO_CONFIG_H
#define REGISTRY_TO_CONFIG_H

#include <string>
#include <Windows.h>

namespace patch::registry_to_config {
    extern bool enabled;

    struct Reg2Cfg;

    Reg2Cfg *createRoot(const std::string &name);
    void close(Reg2Cfg *r2c);

    Reg2Cfg *createSubCfg(Reg2Cfg *r2c, const std::string &name);
    Reg2Cfg *openSubCfg(Reg2Cfg *r2c, const std::string &name);

    bool writeBytes(Reg2Cfg *r2c, const std::string &field, const void *data, size_t size);
    size_t readBytesSize(Reg2Cfg *r2c, const std::string &field);
    bool readBytes(Reg2Cfg *r2c, const std::string &field, void *data, size_t size);

    bool writeInt(Reg2Cfg *r2c, const std::string &field, int value);
    bool readInt(Reg2Cfg *r2c, const std::string &field, int &value);

    bool writeGuid(Reg2Cfg *r2c, const std::string &field, const GUID *value);
    bool readGuid(Reg2Cfg *r2c, const std::string &field, GUID *value);

    bool writeString(Reg2Cfg *r2c, const std::string &field, const char *value);
    bool readString(Reg2Cfg *r2c, const std::string &field, char *buf, size_t bufSize);


};



#endif //REGISTRY_TO_CONFIG_H
