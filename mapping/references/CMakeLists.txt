
set(TARGET references)


add_library(${TARGET} STATIC
        VaReloc.cpp
        Symbol.cpp
        )
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_LIST_DIR})

