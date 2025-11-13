cmake_minimum_required(VERSION 3.15)

project(SIAP_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# SIAP Static Library
file(GLOB_RECURSE SIAP_SOURCES "Source/SIAP/*.c")
file(GLOB_RECURSE SIAP_HEADERS "Source/SIAP/include/*.h")

add_library(siap STATIC ${SIAP_SOURCES} ${SIAP_HEADERS})
target_include_directories(siap PUBLIC "Source/SIAP")
target_link_libraries(siap PUBLIC qsc)

# SIAP Server
file(GLOB_RECURSE SIAP_SERVER_SOURCES "Source/Server/*.c")

add_executable(siap_server ${SIAP_SERVER_SOURCES})
target_include_directories(siap_server PRIVATE "Source/Server")
target_link_libraries(siap_server PRIVATE siap)

# Warnings
foreach(target siap siap_server)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
