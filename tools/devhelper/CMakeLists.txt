set(TARGET devhelper)

enable_language(ASM_MASM)
add_library(${TARGET} SHARED
        dllmain.cpp
        mimicry.cpp
        console.cpp
        game_version.cpp
        )

target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(${TARGET} PRIVATE DIRECTINPUT_VERSION=0x0500 DIRECT3D_VERSION=0x0600)

add_custom_command(TARGET ${TARGET} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:${TARGET}>
        "${DEV_DK2_DIR}/devht.dll"
        )
