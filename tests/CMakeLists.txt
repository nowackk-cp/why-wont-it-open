file(GLOB NEDEN_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
add_executable(neden_tests ${NEDEN_TEST_SOURCES})
target_link_libraries(neden_tests PRIVATE neden_core)
target_include_directories(neden_tests PRIVATE "${PROJECT_SOURCE_DIR}/core/src")
add_test(NAME neden_tests COMMAND neden_tests)

add_subdirectory(samples)
add_dependencies(neden_tests sample_app sample_crt fakedep_full fakedep_old)
target_compile_definitions(neden_tests PRIVATE
  NEDEN_SAMPLE_APP="$<TARGET_FILE:sample_app>"
  NEDEN_SAMPLE_CRT="$<TARGET_FILE:sample_crt>"
  NEDEN_FAKEDEP_FULL="$<TARGET_FILE:fakedep_full>"
  NEDEN_FAKEDEP_OLD="$<TARGET_FILE:fakedep_old>")
