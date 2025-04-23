//
// Created by DiaLight on 4/6/2025.
//
#include "flame_config.h"

#include <fstream>
#include <iostream>
#include <istream>

#define thread_local
#include <patches/game_version_patch.h>

#include "command_line.h"
#include "toml.hpp"


struct toml_type_config {
    using comment_type  = toml::preserve_comments;

    using boolean_type  = bool;
    using integer_type  = std::int64_t;
    using floating_type = double;
    using string_type   = std::string;

    template<typename T>
    using array_type = std::vector<T>;
    // template<typename K, typename T>
    // using table_type = std::unordered_map<K, T>;
    template<typename K, typename T>
    using table_type = std::map<K, T>;

    static toml::result<integer_type, toml::error_info>
    parse_int(const std::string& str, const toml::source_location &src, const std::uint8_t base) {
        return toml::read_int<integer_type>(str, src, base);
    }
    static toml::result<floating_type, toml::error_info>
    parse_float(const std::string& str, const toml::source_location &src, const bool is_hex) {
        return toml::read_float<floating_type>(str, src, is_hex);
    }
};
using toml_value = toml::basic_value<toml_type_config>;
using toml_table = typename toml_value::table_type;
using toml_array = typename toml_value::array_type;

bool flame_config::operator==(const flame_value& lhs, const flame_value& rhs) {
    if (lhs.ty != rhs.ty) return false;
    switch (lhs.ty) {
    case VT_None: return true;
    case VT_String: return lhs.str_value == rhs.str_value;
    case VT_Boolean: return lhs.bool_value == rhs.bool_value;
    case VT_Int: return lhs.int_value == rhs.int_value;
    case VT_Float: return lhs.float_value == rhs.float_value;
    }
    return true;
}

toml_value toTomlValue(const flame_config::flame_value &val) {
    switch (val.ty) {
    case flame_config::VT_String: return {val.str_value};
    case flame_config::VT_Boolean: return {val.bool_value};
    case flame_config::VT_Int: return {val.int_value};
    case flame_config::VT_Float: return {val.float_value};
    default: break;;
    }
    return {};
}
flame_config::flame_value fromTomlValue(toml_value &val) {
    switch (val.type()) {
    case toml::value_t::boolean: return flame_config::flame_value(val.as_boolean());
    case toml::value_t::integer: return flame_config::flame_value((int) val.as_integer());
    case toml::value_t::floating: return flame_config::flame_value((float) val.as_floating());
    case toml::value_t::string: return flame_config::flame_value(val.as_string());
    default: return flame_config::flame_value();
    }
}

std::vector<std::string> split(const std::string &s, const std::string &prefix, char delim) {
    std::vector<std::string> parts;
    std::stringstream ss(s);
    std::string part;
    while(std::getline(ss, part, delim)) {
        if (!part.empty()) parts.push_back(prefix + part);
    }
    return parts;
}

struct toml_location {
    toml_value *node;
    std::string key;

    [[nodiscard]] bool present() const { return node && node->contains(key); }
    [[nodiscard]] toml_value *get() const { return &(*node).at(key); }
    void set(const toml_value &value) const { (*node)[key] = value; }
    void remove() const {
        if (present() && node->is_table()) {
            node->as_table().erase(key);
        }
    }
};

toml_location getOrCreateToml(toml_value &root, const std::string &path) {
    auto parts = split(path, "", ':');
    toml_value *cur = &root;
    for (int i = 0; i < parts.size() - 1; ++i) {
        const std::string& part = parts[i];
        if (!cur->contains(part)) {
            (*cur)[part] = toml_table{};
        }
        if (!cur->is_table()) {
            printf("[warn] %s is not table in path %s\n", path.c_str(), path.c_str());
            (*cur)[part] = toml_table{};
        }
        cur = &cur->at(part);
    }
    const std::string& last = parts[parts.size() - 1];
    return {cur, last};
}

toml_location getToml(toml_value &root, const std::string &path) {
    auto parts = split(path, "", ':');
    toml_value *cur = &root;
    for (int i = 0; i < parts.size() - 1; ++i) {
        const std::string& part = parts[i];
        if (!cur->contains(part)) {
            return {nullptr, ""};
        }
        cur = &cur->at(part);
    }
    const std::string& last = parts[parts.size() - 1];
    return {cur, last};
}
toml_value *getOrNullToml(toml_value &root, const std::string &path) {
    auto loc = getToml(root, path);
    if (!loc.present()) return nullptr;
    return loc.get();
}

void removeToml(toml_value &root, const std::string &path) {
    auto loc = getToml(root, path);
    loc.remove();
}
bool setToml(toml_value &root, const std::string &path, const toml_value& value) {
    auto loc = getOrCreateToml(root, path);
    if(loc.present()) if (auto *oldVal = loc.get()) if (*oldVal == value) return false;
    loc.set(value);
    return true;
}


#define LatestConfigVersion 1
namespace {
    int config_version = -1;
    std::string toml_config_file;
    toml_value toml_config_state;
    toml_value cmdl_state;  // command line args should not affect flame-config.toml but should affect flame_config::get_option, so keep them separate
    bool toml_changed = true;

    struct defined_options_t {
        std::map<std::string, std::unique_ptr<flame_config::defined_flame_option>> dict;

        void add(std::unique_ptr<flame_config::defined_flame_option> &&option) {
            dict[option->path] = std::move(option);
        }
    };
    defined_options_t &defined_options() {
        static defined_options_t impl;
        return impl;
    }
}


toml_value *_get_option(const std::string &path) {
    if (toml_value *cur = getOrNullToml(cmdl_state, path)) return cur;
    if (toml_value *cur = getOrNullToml(toml_config_state, path)) return cur;
    return nullptr;
}
flame_config::flame_value flame_config::get_option(const std::string &path) {
    if (toml_value *cur = _get_option(path)) return fromTomlValue(*cur);
    return flame_value();
}

void flame_config::set_option(const std::string &path, flame_value value) {
    removeToml(cmdl_state, path);
    if (setToml(toml_config_state, path, toTomlValue(value))) {
        toml_changed = true;
    }
    auto &options = defined_options();
    auto it = options.dict.find(path);
    if (it != options.dict.end()) {
        it->second->value = value;
    }
}

void flame_config::_register_flame_option(const char *path, const char *help, flame_value &&defaultValue, flame_value &value) {
    defined_options().add(std::make_unique<defined_flame_option>(path, help, std::move(defaultValue), value));
}

void updateDefinedComments(toml_value &root) {
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        try {
            auto loc = getOrCreateToml(root, opt->path);
            toml_value *val;
            bool isDefault = false;
            if (!loc.present()) {
                loc.set(toTomlValue(opt->defaultValue));
                val = loc.get();
                isDefault = true;
            } else {
                val = loc.get();
                if (fromTomlValue(*val) == opt->defaultValue) {
                    isDefault = true;
                }
            }
            val->comments() = split(opt->help, " ", '\n');
            if (!isDefault) {
                val->comments().push_back(" default: " + toml::format<toml_type_config>(toTomlValue(opt->defaultValue)));
            }
        } catch (const std::exception &ex) {
            std::cout << "error: " << ex.what() << std::endl;
            exit(-1);
        }
    }
    std::string version = patch::game_version_patch::getFileVersion();
    std::replace(version.begin(), version.end(), '\n', ' ');
    root.comments() = std::vector<std::string> {
        " Flame config generated by " + version,
        " Warning: this config is controlled by Flame and DKII",
        " Comments/docs is rewrite every config save. Any manual changes to comments will be erased",
        " if you want edit/add docs to values, please edit them in the the Flame source code",
        " Extra sections and values not controlled by Flame and DKII will be erased",
        " You can made one-time change to any value in config by command line arguments. Use -h for help"
    };
}

void set_cmdl_option(const std::string &path, flame_config::flame_value value) {
    toml_value toml_value = toTomlValue(value);
    setToml(cmdl_state, path, toml_value);
}

void applyDefaultsIfAbsent() {
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        try {
            auto loc = getOrCreateToml(toml_config_state, opt->path);
            if (!loc.present()) {
                loc.set(toTomlValue(opt->defaultValue));
            }
        } catch (const std::exception &ex) {
            std::cout << "error: " << ex.what() << std::endl;
            exit(-1);
        }
    }
}

void vec_remove(std::vector<std::string> &vec, const std::string &val) {
    vec.erase(std::remove(vec.begin(), vec.end(), val), vec.end());
}
bool parse_boolean(const std::string &val) {
    if (val == "false") return false;
    if (val == "0") return false;
    return true;
}
bool processCommandLine(std::map<std::string, std::string> &unused_dict, std::vector<std::string> &unused_flags, flame_config::defined_flame_option &opt, const std::string &key) {
    if (opt.defaultValue.ty == flame_config::VT_Boolean) {  // flag
        if (cmdl::hasFlag(key)) {
            set_cmdl_option(opt.path, flame_config::flame_value(true));
            vec_remove(unused_flags, key);
            return true;
        }
    }
    auto it = cmdl::dict.find(key);
    if (it == cmdl::dict.end()) return false;
    unused_dict.erase(key);
    try {
        flame_config::flame_value value;
        switch (opt.defaultValue.ty) {
        case flame_config::VT_None: break;
        case flame_config::VT_String: value = flame_config::flame_value(it->second); break;
        case flame_config::VT_Boolean: value = flame_config::flame_value(parse_boolean(it->second)); break;
        case flame_config::VT_Int: value = flame_config::flame_value(std::stoi(it->second)); break;
        case flame_config::VT_Float: value = flame_config::flame_value(std::stof(it->second)); break;
        }
        set_cmdl_option(opt.path, value);
    } catch (const std::exception &e) {
        std::cout << "error: failed to parse command line option " << opt.path << " " << e.what() << std::endl;
        exit(-1);
    }
    return false;
}
void applyCommandLine() {
    std::map<std::string, std::string> unused_dict = cmdl::dict;
    std::vector<std::string> unused_flags = cmdl::flags;
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        std::string key = opt->path;
        toLowerCase(key);
        if (processCommandLine(unused_dict, unused_flags, *opt, key)) continue;
        if (key.starts_with("dk2:")) {
            key = key.substr(4);
            processCommandLine(unused_dict, unused_flags, *opt, key);
        } else if (key.starts_with("flame:")) {
            key = key.substr(6);
            processCommandLine(unused_dict, unused_flags, *opt, key);
        }
    }
    for (auto &e : unused_dict) {
        printf("[warn]: unused command line option -%s=%s\n", e.first.c_str(), e.second.c_str());
    }
    for (auto &key : unused_flags) {
        printf("[warn]: unused command line flag -%s\n", key.c_str());
    }
}

void loadDefinedOptions() {
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;

        if (toml_value *cur = _get_option(opt->path)) {
            auto value = fromTomlValue(*cur);
            if (value.ty == opt->defaultValue.ty) {
                opt->value = value;
                continue;
            }
        }
        opt->value = opt->defaultValue;
    }
}

void visitTable(const std::string &path, toml_value &cur, const std::function<void(const std::string &, toml_location &&)> &visitValue) {
    for (auto &e : cur.as_table()) {
        if (e.second.is_table()) {
            visitTable(path + ":" + e.first, e.second, visitValue);
        } else {
            std::string vpath = path + ":" + e.first;
            visitValue(vpath.substr(1), {&cur, e.first});
        }
    }
}
void removeUnusedEntries(toml_value &root) {
    if (!root.is_table()) return;
    std::map<std::string, toml_location> values;
    visitTable("", root, [&values](const std::string &path, toml_location &&loc) {
        values[path] = std::move(loc);
    });
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        values.erase(opt->path);
    }
    for (auto &e : values) {
        if (e.first == "version") continue;
        printf("[warning] remove unused config entry %s\n", e.first.c_str());
        e.second.remove();
    }
}
void removeUnusedAndDefaultEntries(toml_value &root) {
    if (!root.is_table()) return;
    std::map<std::string, toml_location> values;
    visitTable("", root, [&values](const std::string &path, toml_location &&loc) {
        values[path] = std::move(loc);
    });
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;

        auto it = values.find(opt->path);
        if (it != values.end()) {
            if (fromTomlValue(*it->second.get()) == opt->defaultValue) {
                continue;
            }
        }
        values.erase(opt->path);
    }
    for (auto &e : values) {
        if (e.first == "version") continue;
        e.second.remove();
    }
}

void removeComments(toml_value &cur) {
    if (cur.is_table()) {
        for (auto &e : cur.as_table()) {
            removeComments(e.second);
        }
    }
    cur.comments().clear();
}
void removeEmptyNodes(toml_table &cur) {
    std::vector<std::string> remove;
    for (auto &e : cur) {
        if (!e.second.is_table()) continue;
        auto &table = e.second.as_table();
        removeEmptyNodes(table);
        if (table.empty()) {
            remove.push_back(e.first);
        }
    }
    for (auto &key : remove) {
        cur.erase(key);
    }
}
void removeEmptyNodes(toml_value &cur) {
    if (cur.is_table()) {
        removeEmptyNodes(cur.as_table());
    }
}

void flame_config::help() {
    std::cout << "DKII-Flame-*.exe [options]" << std::endl;
    std::cout << "options:" << std::endl;
    std::cout << " -h | -help | --help    print this help" << std::endl;
    std::cout << std::endl;
    std::cout << " -v | -version | --version    print flame version" << std::endl;
    std::cout << std::endl;
    std::cout << " -c <file> | --config <file>    load file as flame config" << std::endl;
    std::cout << "    default: flame/config.toml" << std::endl;
    std::cout << std::endl;
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        std::string arg = opt->path;
        if (!arg.contains(':')) continue;  // disable root args
        if (arg.starts_with("flame:")) {
            arg = "[flame:]" + arg.substr(6);
        } else if (arg.starts_with("dk2:")) {
            arg = "[dk2:]" + arg.substr(4);
        }
        auto lines = split(opt->help, " ", '\n');
        if (opt->defaultValue.ty == VT_Boolean && !opt->defaultValue.bool_value) {
            std::cout << " -" << arg;
            for (auto &line : lines) {
                std::cout << "    " << line << std::endl;
            }
        } else {
            std::string ty;
            switch (opt->defaultValue.ty) {
            case VT_None: break;
            case VT_String: ty = "str"; break;
            case VT_Boolean: ty = "bool"; break;
            case VT_Int: ty = "int"; break;
            case VT_Float: ty = "float"; break;
            }
            std::cout << " -" << arg << " " << "<" << ty << ">";
            for (auto &line : lines) {
                std::cout << "    " << line << std::endl;
            }
            std::cout << "    default: " + toml::format<toml_type_config>(toTomlValue(opt->defaultValue)) << std::endl;
        }
        std::cout << std::endl;
    }
}
void flame_config::load(std::string &file) {
    toml_config_file = file;
    try {
        toml_config_state = toml::parse<toml_type_config>(file);
        if (!toml_config_state.contains("version")) {
            toml_config_state["version"] = LatestConfigVersion;
            toml_config_state.at("version").comments().push_back(" Config version");
        }
    } catch (const ::toml::exception &e) {
        std::cout << "failed to load config: " << e.what() << std::endl;
        toml_config_state = toml_table{};
        toml_config_state["version"] = LatestConfigVersion;
        toml_config_state.at("version").comments().push_back(" Config version");
    }
    if (toml_config_state.contains("version")) {
        config_version = toml_config_state.at("version").as_integer();
    }
    applyDefaultsIfAbsent();
    cmdl_state = toml_table{};
    applyCommandLine();
    loadDefinedOptions();
    toml_changed = false;
}

flame_config::define_flame_option<bool> o_hide_docs(
    "hide_docs",
    "Dont add documentation to keys in this config\n",
    false
);

flame_config::define_flame_option<bool> o_hide_defaults(
    "hide_defaults",
    "Dont add options with default values in this config\n",
    false
);

void flame_config::save() {
    std::cout << "[flame_config] save toml config" << std::endl;
    toml_value copy = toml_config_state;
    removeUnusedEntries(copy);
    removeEmptyNodes(copy);
    if (*o_hide_docs) {
        removeComments(copy);
    } else {
        updateDefinedComments(copy);
    }
    if (*o_hide_defaults) {
        removeUnusedAndDefaultEntries(copy);
        removeEmptyNodes(copy);
    }
    try {
        auto config = toml::format<toml_type_config>(copy);
        {
            std::ofstream fout;
            fout.open(toml_config_file);
            fout << config << "\n";
        }
    } catch (const ::toml::exception &e) {
        std::cout << "failed to save config: " << e.what() << std::endl;
    }
    toml_changed = false;
}
bool flame_config::changed() {
    return toml_changed;
}

void mergeOptions(toml_value &dst, toml_value &src) {
    for (auto &e : defined_options().dict) {
        auto &opt = e.second;
        if (toml_value *cur = getOrNullToml(src, opt->path)) {
            auto loc = getOrCreateToml(dst, opt->path);
            loc.set(*cur);
        }
    }
}


std::string flame_config::shortDump() {
    toml_value copy = toml_config_state;
    mergeOptions(copy, cmdl_state);
    removeUnusedAndDefaultEntries(copy);
    removeEmptyNodes(copy);
    removeComments(copy);
    try {
        return toml::format<toml_type_config>(copy);
    } catch (const ::toml::exception &e) {
        std::cout << "failed to format config: " << e.what() << std::endl;
        return "";
    }
}
