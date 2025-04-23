//
// Created by DiaLight on 4/6/2025.
//

#ifndef FLAME_CONFIG_H
#define FLAME_CONFIG_H

#include <string>
#include <vector>
#include <type_traits>


namespace flame_config {
    enum value_type {
        VT_None,
        VT_String,
        VT_Boolean,
        VT_Int,
        VT_Float,
    };

    struct flame_value {

        typedef std::string string_ty;
        typedef bool bool_ty;
        typedef int int_ty;
        typedef float float_ty;

        value_type ty;
        union {
            string_ty str_value;
            bool_ty bool_value;
            int_ty int_value;
            float_ty float_value;
        };

        explicit flame_value() : ty(VT_None) { int_value = 0; }
        explicit flame_value(const char *value) : ty(VT_String) { new (&str_value) string_ty(value); }
        explicit flame_value(const std::string &value) : ty(VT_String) { new (&str_value) string_ty(value); }
        explicit flame_value(bool value) : ty(VT_Boolean) { new (&bool_value) bool_ty(value); }
        explicit flame_value(int value) : ty(VT_Int) { new (&int_value) int_ty(value); }
        explicit flame_value(float value) : ty(VT_Float) { new (&float_value) float_ty(value); }
        flame_value(const flame_value &other) : flame_value() { *this = other; }
        flame_value(flame_value &&other) noexcept : flame_value() { *this = std::move(other); }

        flame_value & operator=(const flame_value &other) {
            if (this == &other) return *this;
            cleanup();
            ty = other.ty;
            switch (ty) {
            case VT_None: break;
            case VT_String: new (&str_value) string_ty(other.str_value); break;
            case VT_Boolean: new (&bool_value) bool_ty(other.bool_value); break;
            case VT_Int: new (&int_value) int_ty(other.int_value); break;
            case VT_Float: new (&float_value) float_ty(other.float_value); break;
            }
            return *this;
        }

        flame_value & operator=(flame_value &&other) noexcept {
            if (this == &other) return *this;
            cleanup();
            ty = other.ty;
            switch (ty) {
            case VT_None: break;
            case VT_String: new (&str_value) string_ty(std::move(other.str_value)); break;
            case VT_Boolean: new (&bool_value) bool_ty(std::move(other.bool_value)); break;
            case VT_Int: new (&int_value) int_ty(std::move(other.int_value)); break;
            case VT_Float: new (&float_value) float_ty(std::move(other.float_value)); break;
            }
            other.ty = VT_Int;
            new (&other.int_value) int_ty(0);
            return *this;
        }

        ~flame_value() {
            cleanup();
        }

        std::string to_string() const {
            switch (ty) {
            case VT_None: break;
            case VT_String: return '"' + str_value + '"';
            case VT_Boolean: return bool_value ? "true" : "false";
            case VT_Int: return std::to_string(int_value);
            case VT_Float: return std::to_string(float_value);
            }
            return "";
        }

    private:
        void cleanup() {
            switch (ty) {
            case VT_None: break;
            case VT_String: str_value.~string_ty(); break;
            case VT_Boolean: bool_value.~bool_ty(); break;
            case VT_Int: int_value.~int_ty(); break;
            case VT_Float: float_value.~float_ty(); break;
            }
        }

    };

    bool operator==(const flame_value& lhs, const flame_value& rhs);

    flame_value get_option(const std::string &path);
    void set_option(const std::string &path, flame_value value);

    void help();
    void load(std::string &file);
    void save();
    bool changed();
    std::string shortDump();


    struct defined_flame_option {
        const char *path;
        const char *help;

        flame_value defaultValue;
        flame_value &value;

        defined_flame_option(const char *path, const char *help, flame_value &&defaultValue, flame_value &value)
            : path(path), help(help), defaultValue(std::move(defaultValue)), value(value) {
        }
    };

    void _register_flame_option(const char *path, const char *help, flame_value &&defaultValue, flame_value &value);

    template <typename T>
    struct define_flame_option {

        const char *path = NULL;
        flame_value value;
        define_flame_option() = delete;
        define_flame_option(const char *path, const char *help, T defaultValue) : path(path) { _register_flame_option(path, help, flame_value(defaultValue), value); }


        template<typename = std::enable_if<std::is_same<T, std::string>::value>::type>
        void set(T &value) {
            set_option(path, flame_value(value));
        }
        template<typename = std::enable_if<!std::is_same<T, std::string>::value>::type>
        void set(T value) {
            set_option(path, flame_value(value));
        }


        template<typename = std::enable_if<std::is_same<T, std::string>::value>::type>
        T &get() {
            if (value.ty != VT_String) {
                printf("invalid option %s type. %d != %d\n", path, value.ty, VT_String);
                exit(-1);
            }
            return value.str_value;
        }
        template<typename = std::enable_if<std::is_same<T, std::string>::value>::type>
        _NODISCARD _CONSTEXPR23 T &operator*() noexcept {
            return get();
        }
        template<typename = std::enable_if<std::is_same<T, std::string>::value>::type>
        _NODISCARD _CONSTEXPR23 T *operator->() noexcept {
            return &get();
        }

        template<typename = std::enable_if<!std::is_same<T, std::string>::value>::type>
        T get() const {
            if constexpr (std::is_same_v<T, bool>) {
                if (value.ty != VT_Boolean) return false;
                return value.bool_value;
            }
            if constexpr (std::is_same_v<T, int>) {
                if (value.ty != VT_Int) {
                    printf("invalid option %s type. %d != %d\n", path, value.ty, VT_Int);
                    exit(-1);
                }
                return value.int_value;
            }
            if constexpr (std::is_same_v<T, float>) {
                if (value.ty != VT_Float) {
                    printf("invalid option %s type. %d != %d\n", path, value.ty, VT_Float);
                    exit(-1);
                }
                return value.float_value;
            }
            static_assert("invalid template type");
            return {};
        }
        template<typename = std::enable_if<!std::is_same<T, std::string>::value>::type>
        _NODISCARD _CONSTEXPR23 T operator*() const noexcept {
            return get();
        }

    };

}

#endif //FLAME_CONFIG_H
