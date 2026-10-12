cmake_minimum_required(VERSION 3.21)
project(why_wont_it_open VERSION 0.1.0 LANGUAGES C CXX)

if(NOT WIN32)
  message(FATAL_ERROR "This project targets Windows only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Static CRT (/MT): the tool must start on machines that lack the VC++ runtime.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(MSVC)
  add_compile_options(/W4 /permissive- /utf-8 /EHsc /Zc:__cplusplus)
  add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(WARNING "Release builds are expected to be 32-bit (x86). Configure with -A Win32.")
endif()

option(NEDEN_FUZZ "Build libFuzzer targets" OFF)
option(NEDEN_TOOLS "Build developer tools (test-data generators)" OFF)

add_subdirectory(core)
add_subdirectory(cli)
add_subdirectory(gui)

if(NEDEN_TOOLS)
  add_subdirectory(tools)
endif()

include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()

if(NEDEN_FUZZ)
  add_subdirectory(fuzz)
endif()
