find_program(LIB_PROGRAM lib)
find_program(DUMPBIN_PROGRAM dumpbin)

set(GENLIB_LIB weanetr.lib)

set(ABS_GENLIB_LIB ${GENLIB_LIB})
list(TRANSFORM ABS_GENLIB_LIB PREPEND "${CMAKE_CURRENT_LIST_DIR}/")
add_custom_command(
        OUTPUT ${ABS_GENLIB_LIB}
        COMMAND cmd /C ${CMAKE_HOME_DIRECTORY}/tools/genlib/gen_map.bat
        ${DUMPBIN_PROGRAM} ${CMAKE_HOME_DIRECTORY}/libs/weanetr_dll/WEANETR.dll weanetr.def WEANETR
        COMMAND cmd /C ${CMAKE_HOME_DIRECTORY}/tools/genlib/gen_lib.bat
        ${LIB_PROGRAM} weanetr.def ${ABS_GENLIB_LIB}
        DEPENDS ${CMAKE_HOME_DIRECTORY}/libs/weanetr_dll/WEANETR.dll
        COMMENT "genlib ${GENLIB_LIB}"
)

set(TARGET weanetr_genlib)
add_library(${TARGET} INTERFACE
        ${GENLIB_LIB}  # make target depend on lib file building
        )
target_link_libraries(${TARGET} INTERFACE ${GENLIB_LIB})  # make target share lib dependency with others
target_link_directories(${TARGET} INTERFACE ${CMAKE_CURRENT_LIST_DIR})  # make other targets able to find lib file
