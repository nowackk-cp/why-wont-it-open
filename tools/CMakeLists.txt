# Developer tools; built only with -DNEDEN_TOOLS=ON.
add_executable(gen_testdata gen_testdata.cpp)
target_link_libraries(gen_testdata PRIVATE neden_core)
target_include_directories(gen_testdata PRIVATE "${PROJECT_SOURCE_DIR}/tests")
