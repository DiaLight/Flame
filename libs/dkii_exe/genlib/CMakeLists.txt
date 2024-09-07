find_program(LIB_PROGRAM lib)
find_program(DUMPBIN_PROGRAM dumpbin)

set(GENLIB_LIB dkii.lib)

set(ABS_GENLIB_LIB ${GENLIB_LIB})
list(TRANSFORM ABS_GENLIB_LIB PREPEND "${CMAKE_CURRENT_LIST_DIR}/")

#get_target_property(GENAPI_SRCS genlib_dkii SOURCES)
#get_target_property(SOURCE_DIR genlib_dkii SOURCE_DIR)
#set(ABS_GENAPI_SRCS ${GENAPI_SRCS})
#list(TRANSFORM ABS_GENAPI_SRCS PREPEND "${SOURCE_DIR}/")
add_custom_command(
        OUTPUT ${ABS_GENLIB_LIB} ${CMAKE_CURRENT_LIST_DIR}/dkii_symbols.map
#        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_HOME_DIRECTORY}/mapping/ida
#        ${Python3_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/genlib_dkii/main.py
        COMMAND $<TARGET_FILE:genlib_dkii>
        -sgmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        -def_file ${CMAKE_CURRENT_LIST_DIR}/dkii.def
        -replace_globals ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        -exp_file ${CMAKE_CURRENT_LIST_DIR}/dkii_exp.def
        -map_file ${CMAKE_CURRENT_LIST_DIR}/dkii_symbols.map
        COMMAND cmd /C ${CMAKE_HOME_DIRECTORY}/tools/genlib/gen_lib.bat
        ${LIB_PROGRAM} ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.def ${ABS_GENLIB_LIB}
        DEPENDS
#        ${ABS_GENAPI_SRCS}
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        COMMENT "genlib DKII.EXE"
)


set(TARGET dkii_genlib)
add_library(${TARGET} INTERFACE
        ${GENLIB_LIB}  # make target depend on lib file building
        )
target_link_libraries(${TARGET} INTERFACE ${GENLIB_LIB})  # make target share lib dependency with others
target_link_directories(${TARGET} INTERFACE ${CMAKE_CURRENT_LIST_DIR})  # make other targets able to find lib file

