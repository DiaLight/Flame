
set(TARGET sgmap)


add_library(${TARGET} STATIC
        SGMap.cpp
        LineIter.cpp
        ScopeLineIter.cpp
        Type.cpp
        Struct.cpp
        Global.cpp
        )
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_LIST_DIR})

