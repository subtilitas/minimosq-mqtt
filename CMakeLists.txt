cmake_minimum_required(VERSION 3.16)
project(minimosq VERSION 0.3.4 LANGUAGES CXX)

# minimosq is a header-only library. Consumers only need the include path
# and a C++17 compiler; nothing is compiled for the library itself.
add_library(minimosq INTERFACE)
add_library(minimosq::minimosq ALIAS minimosq)
target_include_directories(minimosq INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>)
target_compile_features(minimosq INTERFACE cxx_std_17)

# Tests and examples are only built when minimosq is the top-level project.
if(CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    option(MINIMOSQ_BUILD_TESTS "Build the unit tests" ON)
    option(MINIMOSQ_BUILD_EXAMPLES "Build the example brokers (POSIX only)" ON)
    option(MINIMOSQ_WERROR "Treat warnings as errors" OFF)

    # Strict build flags used for everything in this repository. The library
    # is exception-free and RTTI-free by construction; building the tests with
    # -fno-exceptions/-fno-rtti keeps it honest.
    add_library(minimosq_build_flags INTERFACE)
    if(NOT MSVC)
        target_compile_options(minimosq_build_flags INTERFACE
            -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow
            -fno-exceptions -fno-rtti)
        if(MINIMOSQ_WERROR)
            target_compile_options(minimosq_build_flags INTERFACE -Werror)
        endif()
    else()
        target_compile_options(minimosq_build_flags INTERFACE /W4)
        if(MINIMOSQ_WERROR)
            target_compile_options(minimosq_build_flags INTERFACE /WX)
        endif()
    endif()

    if(MINIMOSQ_BUILD_TESTS)
        enable_testing()
        add_subdirectory(tests)
    endif()

    if(MINIMOSQ_BUILD_EXAMPLES AND UNIX)
        add_subdirectory(examples)
    endif()

    # Host-side tools (documentation build).
    option(MINIMOSQ_BUILD_TOOLS "Build the developer tools" ON)
    if(MINIMOSQ_BUILD_TOOLS)
        add_executable(minimosq_footprint tools/footprint.cpp)
        target_link_libraries(minimosq_footprint
            PRIVATE minimosq::minimosq minimosq_build_flags)
    endif()
endif()
