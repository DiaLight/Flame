//
// Created by DiaLight on 23.06.2024.
//
#include "ScopeLineIter.h"
#include <algorithm>


bool ScopeLineIter::hasPadding(std::string &line) const {
    auto *p = line.c_str();
    for (int i = 0; i < this->level; ++i) {
        if(strncmp(p, "  ", 2) != 0) return false;
        p += 2;
    }
    return true;
}

std::string *ScopeLineIter::next() {
    std::string *line = it.next();
    if(line == nullptr) return nullptr;
    if(!hasPadding(*line)) {
        it.use_last = true;
        return nullptr;
    }
    *line = line->substr(level * 2);
    return line;
}

void split(const std::string &str, const std::string &delimiter, std::vector<std::string> &parts, size_t limit) {
    size_t lastPos = 0;
    size_t pos = 0;
    std::string token;
    for (int i = 0; i < limit; ++i) {
        if((pos = str.find(delimiter, lastPos)) == std::string::npos) break;
        token = str.substr(lastPos, pos - lastPos);
        parts.push_back(token);
        lastPos = pos + delimiter.length();
    }
    parts.push_back(str.substr(lastPos));
}

bool _parseShort(const std::string &line, std::string &name, std::map<std::string, std::string> &shortProps) {
    std::vector<std::string> parts;
    split(line, ": ", parts, 1);
    name = parts[0];
    std::string props = parts[1];
    parts.clear();
    split(props, ",", parts);
    for (auto &part : parts) {
        std::vector<std::string> parts2;
        split(part, "=", parts2, 1);
        if(parts2.size() != 2) return false;
        std::string key = parts2[0];
        std::string value = parts2[1];
        shortProps.insert(std::make_pair(key, value));
    }
    return true;
}

bool parseHexInt32(const std::string &str, uint32_t &val) {
    val = std::stoul(str, nullptr, 16);
    return true;
}
bool parseInt(const std::string &str, size_t &val) {
    if(str.empty()) return false;
    val = std::stoul(str);
    return true;
}

std::string getStrOptional(std::map<std::string, std::string> &shortProps, const std::string &key, const std::string &def) {
    auto it = shortProps.find(key);
    if(it != shortProps.end()) {
        return it->second;
    }
    return def;
}

bool getBoolOptional(std::map<std::string, std::string> &shortProps, const std::string &key, bool def) {
    auto val = getStrOptional(shortProps, key, "");
    if(val.empty()) return def;
    std::transform(
            val.begin(), val.end(), val.begin(),
            [](unsigned char c){ return std::tolower(c); }
    );
    return val == "true";
}
size_t getIntOptional(std::map<std::string, std::string> &shortProps, const std::string &key, size_t def) {
    auto val = getStrOptional(shortProps, key, "");
    if(val.empty()) return def;
    size_t intVal;
    if(!parseInt(val, intVal)) return def;
    return intVal;
}
