set(TARGET delinker)

add_executable(${TARGET}
        main.cpp
        chunk/ChunkRef.cpp
        chunk/Chunk.cpp
        dk2_170.cpp
        CoffBuilder.cpp
)
target_link_libraries(${TARGET} PRIVATE sgmap references msvc_mangler)


