set(TARGET genapi)

add_custom_target(${TARGET}
        SOURCES
        main.py
        gen_utils.py
        dk2cxx.py
        gen_functions_h.py
        gen_globals_h.py
        gen_struct_h.py
        )
