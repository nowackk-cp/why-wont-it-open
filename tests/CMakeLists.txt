add_executable(neden_tests test_main.cpp)
target_link_libraries(neden_tests PRIVATE neden_core)
add_test(NAME neden_tests COMMAND neden_tests)
