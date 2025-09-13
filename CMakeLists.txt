cmake_minimum_required(VERSION 3.25)
project(flame)

set(CMAKE_CXX_STANDARD 23)

option(NO_VCRUNTIME "Will remove dependency on VCRUNTIME*.dll")
if(NO_VCRUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

option(USE_CONFIGURE_DATE "Add configure date marker in output build")
option(DK2_DIR "Dungeon Keeper 2 directory (for comfortable development)")

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

define_property(
        TARGET
        PROPERTY TARGET_MAP_FILE
        BRIEF_DOCS "Mapping file name"
        FULL_DOCS "...")

if(USE_CONFIGURE_DATE)
  string(TIMESTAMP CONFIGURE_DATE "%y%m%d")
endif ()

include(resources/CMakeLists.txt)

set(OUTPUT_VERSION "${VER_PRODUCT_NUMBER}.${VER_PRODUCT_VERSION}.${VER_BUILD_NUMBER}")
if(CONFIGURE_DATE)
  string(APPEND OUTPUT_VERSION "-${CONFIGURE_DATE}")
endif ()

add_subdirectory(mapping)
add_subdirectory(tools)
add_subdirectory(libs)
add_subdirectory(src)

if(DK2_DIR)
  message(STATUS "Dungeon Keeper 2 directory: ${DK2_DIR}")
  if(NOT EXISTS "${DK2_DIR}/DKII-DX.EXE")
    message(FATAL_ERROR "\"${DK2_DIR}/DKII-DX.EXE\" is not found")
  endif()
  set(PDB_COPY_COMMANDS)
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(PDB_COPY_COMMANDS
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_PDB_FILE:flame> "${DK2_DIR}/flame/Flame.pdb"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_PDB_FILE:dkii_dll_stub> "${DK2_DIR}/flame/DKII.pdb"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_PDB_FILE:flame_loader> "${DK2_DIR}/flame/PATCH.pdb"
    )
  endif()
  add_custom_target(flame_dev
          DEPENDS flame dkii_dll_stub flame_loader
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:flame> "${DK2_DIR}/flame/Flame.dll"
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:dkii_dll_stub> "${DK2_DIR}/flame/DKII.dll"
          COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:flame_loader> "${DK2_DIR}/PATCH.dll"
          ${PDB_COPY_COMMANDS}
  )
endif()

set(OUTPUT_SUFFIX)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(OUTPUT_SUFFIX "-debug")
endif ()
add_custom_target(get_artifact_name
        COMMAND ${CMAKE_COMMAND} -E echo "Flame-${OUTPUT_VERSION}${OUTPUT_SUFFIX}" >> ${CMAKE_CURRENT_BINARY_DIR}/artifact_name.txt
        WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}
)

set(Python_EXECUTABLE "")  # disable warning: Manually-specified variables were not used by the project
