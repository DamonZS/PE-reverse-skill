cmake_minimum_required(VERSION 3.20)
project(dll_export_proxy LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "This project must use a Windows-targeting toolchain")
endif()

set(DLL_PROXY_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
cmake_path(
    IS_PREFIX DLL_PROXY_SOURCE_ROOT
    "${CMAKE_CURRENT_BINARY_DIR}"
    NORMALIZE
    DLL_PROXY_BUILD_INSIDE)
if(NOT DLL_PROXY_BUILD_INSIDE)
    message(FATAL_ERROR "Build output must remain inside the generated proxy project")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Compiler pointer width does not match x64")
endif()

add_library(dll_proxy SHARED proxy.c)
if(MSVC)
    target_link_options(dll_proxy PRIVATE "/DEF:${CMAKE_CURRENT_SOURCE_DIR}/proxy.def")
else()
    target_sources(dll_proxy PRIVATE proxy.def)
endif()
set_target_properties(dll_proxy PROPERTIES
    PREFIX ""
    OUTPUT_NAME "fixture"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
add_custom_command(TARGET dll_proxy POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/backing/fixture_original.dll"
        "$<TARGET_FILE_DIR:dll_proxy>/fixture_original.dll"
    VERBATIM)
