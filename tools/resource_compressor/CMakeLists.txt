set(TARGET resource_compressor)

add_executable(${TARGET}
        main.cpp
        Fpo.cpp
)
target_link_libraries(${TARGET} PRIVATE Cabinet)
