
add_subdirectory(delinked)


set(API_HEADERS
        api/dk2_functions.h
        api/dk2_globals.h
        )

set(ABS_API_HEADERS ${API_HEADERS})
list(TRANSFORM ABS_API_HEADERS PREPEND "${CMAKE_CURRENT_LIST_DIR}/")

get_target_property(GENAPI_SRCS genapi SOURCES)
get_target_property(SOURCE_DIR genapi SOURCE_DIR)
set(ABS_GENAPI_SRCS ${GENAPI_SRCS})
list(TRANSFORM ABS_GENAPI_SRCS PREPEND "${SOURCE_DIR}/")
add_custom_command(
        OUTPUT ${ABS_API_HEADERS}
        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_HOME_DIRECTORY}/mapping/ida
        ${Python3_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/genapi/main.py
        -sgmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        -headers ${CMAKE_CURRENT_LIST_DIR}/api
        DEPENDS ${ABS_GENAPI_SRCS}
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        COMMENT "genapi DKII.EXE"
)

add_library(dkii_exe_api INTERFACE
        ${API_HEADERS}
        )
target_include_directories(dkii_exe_api INTERFACE api)
target_include_directories(dkii_exe_api INTERFACE 3rdparty/mpeg2codec-1.2_19960719/src/mpeg2enc)

