set(TARGET dkii_res)

set(VER_PRODUCT_NUMBER 1)
set(VER_PRODUCT_VERSION 7)
set(VER_BUILD_NUMBER 0)
set(VER_REVISION_NUMBER 0)
if(CONFIGURE_DATE)
    set(VER_FILE_SUFFIX "${CONFIGURE_DATE}")
endif ()
set(VER_PROJECT_URL "https://github.com/DiaLight/Flame")
set(VER_PRODUCT_NAME "DKII-Flame")
set(VER_DESCRIPTION "DKII unofficial relinking with replaces")

set(VER_RES_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(VER_COMMENTS "url: ${VER_PROJECT_URL}")
set(VER_FILE_SUFFIX " Flame build")
if(NOT VER_BUILD_NUMBER EQUAL 0)
    string(APPEND VER_FILE_SUFFIX ".${VER_BUILD_NUMBER}")
endif ()
if(CONFIGURE_DATE)
    string(APPEND VER_COMMENTS ", date: ${CONFIGURE_DATE}")
    string(APPEND VER_FILE_SUFFIX " ${CONFIGURE_DATE}")
endif ()
if(GIT_SHA1)
    string(APPEND VER_COMMENTS ", commit: ${GIT_SHA1} ${GIT_DATE} ${GIT_COMMIT_SUBJECT}")
    string(APPEND VER_FILE_SUFFIX " ${GIT_SHORT_SHA1}")
endif ()

configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/resources.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/resources.rc
        @ONLY)

set(DKII_RESOURCES_FILE ${CMAKE_CURRENT_BINARY_DIR}/resources.rc)
