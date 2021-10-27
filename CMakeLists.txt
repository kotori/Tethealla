cmake_minimum_required(VERSION 3.8)

project(Tethealla VERSION 1.0.0 LANGUAGES C)

# Require out-of-source builds. To ensure the user doesn't screw up the source.
file(TO_CMAKE_PATH "${PROJECT_BINARY_DIR}/CMakeLists.txt" LOC_PATH)
if(EXISTS "${LOC_PATH}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please make a build subdirectory. Feel free to remove CMakeCache.txt and CMakeFiles.")
endif()

OPTION (EXTRAS "Build the newtable, convert_quest, and convert_unitxt projects" OFF)

# default to a release build
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Put the resulting binaries in the bin directory.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/deploy/bin)

# Here we configure the NO_SQL switch for swapping between MySQL and dat files
option (NO_SQL "DO NOT use the MySQL database engine, instead use dat files" ON)

# Here we create our header file based on our configuration options.
configure_file (
  "${PROJECT_SOURCE_DIR}/TetheallaConfig.h.in"
  "${PROJECT_BINARY_DIR}/TetheallaConfig.h"
)

# silence the compiler a bit
add_definitions(-w)

include_directories("${PROJECT_BINARY_DIR}")

if (NO_SQL)
    message (STATUS "Storage: Dat mode enabled. MySQL disabled.")
else()
    message (STATUS "Storage: MySQL mode enabled. DAT disabled.")
endif()

# Only include char_export if MySQL mode is active.
if (NOT NO_SQL)
    add_subdirectory (src/char_export)
endif()
add_subdirectory (src/make_key)
add_subdirectory (src/account_add)
add_subdirectory (src/patch_server)
add_subdirectory (src/login_server)
add_subdirectory (src/ship_server)

# Other projects I don't use, but I'm sure someone does.
if (${EXTRAS})
    add_subdirectory (src/newtable)
    add_subdirectory (src/convert_quest)
    add_subdirectory (src/convert_unitxt)
endif()

file(GLOB MY_SERVER_DATA
  "${CMAKE_CURRENT_SOURCE_DIR}/data/*"
)
message (STATUS "Copying extra server data to ${CMAKE_CURRENT_BINARY_DIR}/deploy/")
file(COPY ${MY_SERVER_DATA} DESTINATION "${CMAKE_CURRENT_BINARY_DIR}/deploy/")
