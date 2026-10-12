# Real binaries produced by the MSVC toolchain, analysed (never run) by the
# integration tests in tests/test_integration.cpp.
enable_language(C)

add_library(fakedep_full SHARED fakedep.c fakedep_full.def)
add_library(fakedep_old SHARED fakedep.c fakedep_old.def)
foreach(t fakedep_full fakedep_old)
  set_target_properties(${t} PROPERTIES
    OUTPUT_NAME fakedep
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${t}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/${t}")
endforeach()

add_executable(sample_app sample_app.c)
target_link_libraries(sample_app PRIVATE fakedep_full)

add_executable(sample_crt sample_crt.c)
set_target_properties(sample_crt PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
