set(TARGET genlib_dkii)

#add_custom_target(${TARGET}
#        SOURCES
#        main.py
#        )

add_executable(${TARGET}
        main.cpp
        )
target_link_libraries(${TARGET} PRIVATE sgmap references msvc_mangler)
