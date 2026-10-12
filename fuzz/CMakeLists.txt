# libFuzzer targets (MSVC /fsanitize=fuzzer). Configure with -DNEDEN_FUZZ=ON.
if(NOT MSVC)
  message(FATAL_ERROR "NEDEN_FUZZ currently supports MSVC only.")
endif()

# The parser is compiled straight into the fuzz target (instead of linking
# neden_core) so that it gets ASan + coverage instrumentation without
# affecting the shipping library, CLI or tests.
add_executable(fuzz_pe fuzz_pe.cpp "${PROJECT_SOURCE_DIR}/core/src/pe/pe.cpp")
target_include_directories(fuzz_pe PRIVATE "${PROJECT_SOURCE_DIR}/core/include")
target_compile_options(fuzz_pe PRIVATE /fsanitize=address /fsanitize=fuzzer /Zi)
target_link_options(fuzz_pe PRIVATE /DEBUG)

# Tiny helper that writes seed files generated with tests/pe_builder.h.
add_executable(gen_seeds gen_seeds.cpp)
target_include_directories(gen_seeds PRIVATE "${PROJECT_SOURCE_DIR}/tests")
target_link_libraries(gen_seeds PRIVATE neden_core)

# The ASan runtime DLL sits next to the compiler (bin/Host<host>/<target>);
# copy it beside the fuzzer so it starts without a developer prompt.
get_filename_component(NEDEN_CL_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
file(GLOB NEDEN_ASAN_DLL "${NEDEN_CL_DIR}/clang_rt.asan_dynamic-*.dll")
if(NEDEN_ASAN_DLL)
  add_custom_command(TARGET fuzz_pe POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different ${NEDEN_ASAN_DLL} "$<TARGET_FILE_DIR:fuzz_pe>"
    VERBATIM)
else()
  message(WARNING "ASan runtime DLL not found next to ${CMAKE_CXX_COMPILER}; put it on PATH to run fuzz_pe.")
endif()
