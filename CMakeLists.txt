cmake_minimum_required(VERSION 3.25)
project(flame)

set(CMAKE_CXX_STANDARD 23)

option(USE_CONFIGURE_DATE "Add configure date marker in output build")

# generate pdb to use debuggers with release builds
string(APPEND CMAKE_EXE_LINKER_FLAGS_RELEASE " /debug")

message(STATUS "CMAKE_SYSTEM_VERSION: ${CMAKE_SYSTEM_VERSION}")
message(STATUS "CMAKE_RC_COMPILER: ${CMAKE_RC_COMPILER}")
message(STATUS "CMAKE_CXX_COMPILER: ${CMAKE_CXX_COMPILER}")

# force using python through venv
if(EXISTS ${CMAKE_CURRENT_LIST_DIR}/.venv/Scripts/python.exe)
  set(Python3_EXECUTABLE "${CMAKE_CURRENT_LIST_DIR}/.venv/Scripts/python.exe")
  # test for capstone package installed
  execute_process(COMMAND ${Python3_EXECUTABLE} -c "import capstone" RESULT_VARIABLE EXIT_CODE OUTPUT_QUIET)
else ()
  # create venv
  find_package(Python3 COMPONENTS Interpreter REQUIRED)
  execute_process(COMMAND_ECHO STDOUT COMMAND ${Python3_EXECUTABLE} -m venv ${CMAKE_CURRENT_LIST_DIR}/.venv )
  set(Python3_EXECUTABLE "${CMAKE_CURRENT_LIST_DIR}/.venv/Scripts/python.exe")
  set(EXIT_CODE 1)
endif ()
if(${EXIT_CODE} EQUAL 1)  # not installed
  execute_process(COMMAND_ECHO STDOUT COMMAND ${Python3_EXECUTABLE} -m pip install -U pip wheel )
  execute_process(COMMAND_ECHO STDOUT COMMAND ${Python3_EXECUTABLE} -m pip install -r ${CMAKE_CURRENT_LIST_DIR}/requirements.txt )
endif ()
message(STATUS "Python3 found: ${Python3_EXECUTABLE}")

find_package(Python3 COMPONENTS Interpreter REQUIRED)

find_package(Git REQUIRED)
message(STATUS "Git found: ${GIT_EXECUTABLE}")

# the commit's SHA1, and whether the building workspace was dirty or not
execute_process(COMMAND
        "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=40 --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_SHA1
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND
        "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=7 --dirty
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_SHORT_SHA1
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# the date of the commit
execute_process(COMMAND
        "${GIT_EXECUTABLE}" log -1 --format=%ad --date=local
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_DATE
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

# the subject of the commit
execute_process(COMMAND
        "${GIT_EXECUTABLE}" log -1 --format=%s
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_COMMIT_SUBJECT
        ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "GIT_SHA1: ${GIT_SHA1}")
message(STATUS "GIT_DATE: ${GIT_DATE}")
message(STATUS "GIT_COMMIT_SUBJECT: ${GIT_COMMIT_SUBJECT}")

add_subdirectory(mapping)
add_subdirectory(tools)
add_subdirectory(libs)

define_property(
        TARGET
        PROPERTY TARGET_MAP_FILE
        BRIEF_DOCS "Mapping file name"
        FULL_DOCS "...")

if(USE_CONFIGURE_DATE)
  string(TIMESTAMP CONFIGURE_DATE "%y%m%d.2")
endif ()

include(resources/CMakeLists.txt)

set(OUTPUT_SUFFIX "-${VER_PRODUCT_NUMBER}.${VER_PRODUCT_VERSION}.${VER_BUILD_NUMBER}")
if(CONFIGURE_DATE)
  string(APPEND OUTPUT_SUFFIX "-${CONFIGURE_DATE}")
endif ()
add_subdirectory(src)

