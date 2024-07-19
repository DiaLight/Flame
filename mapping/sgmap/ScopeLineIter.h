//
// Created by DiaLight on 23.06.2024.
//

#ifndef FLAME_SCOPELINEITER_H
#define FLAME_SCOPELINEITER_H

#include "LineIter.h"
#include <vector>
#include <string>
#include <map>


struct ScopeLineIter {

    LineIter &it;
    size_t level;
    size_t start_line_num;

    explicit ScopeLineIter(LineIter &it, size_t level = 0) :
            it(it), level(level), start_line_num(it.line_num) {}

    [[nodiscard]] bool hasPadding(std::string &line) const;

    [[nodiscard]] std::string *next();

};

void split(const std::string &str, const std::string &delimiter, std::vector<std::string> &parts, size_t limit = (-1));

[[nodiscard]] bool _parseShort(const std::string &line, std::string &name, std::map<std::string, std::string> &shortProps);

[[nodiscard]] bool parseHexInt32(const std::string &str, uint32_t &val);
[[nodiscard]] bool parseInt(const std::string &str, size_t &val);

[[nodiscard]] std::string getStrOptional(std::map<std::string, std::string> &shortProps, const std::string &key, const std::string &def);
[[nodiscard]] bool getBoolOptional(std::map<std::string, std::string> &shortProps, const std::string &key, bool def);
[[nodiscard]] size_t getIntOptional(std::map<std::string, std::string> &shortProps, const std::string &key, size_t def);


#endif //FLAME_SCOPELINEITER_H
