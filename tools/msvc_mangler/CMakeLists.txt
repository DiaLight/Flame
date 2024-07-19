set(TARGET msvc_mangler)
add_library(${TARGET} STATIC
        msvc_mangler.cpp
)
target_include_directories(${TARGET} PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(${TARGET} PUBLIC sgmap)


set(TESTS mangler_tests)
add_executable(${TESTS}
        mangler_tests.cpp
        )
target_link_libraries(${TESTS} PRIVATE ${TARGET})

