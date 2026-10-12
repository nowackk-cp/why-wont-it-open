add_library(neden_core STATIC
  src/version.cpp
)
target_include_directories(neden_core PUBLIC include)
target_compile_definitions(neden_core PRIVATE NEDEN_VERSION="${PROJECT_VERSION}")
