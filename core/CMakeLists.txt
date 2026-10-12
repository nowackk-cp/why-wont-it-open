# Embed data/runtimes.json into the library so the tool stays a single exe.
set(NEDEN_KB_JSON "${PROJECT_SOURCE_DIR}/data/runtimes.json")
set(NEDEN_KB_CPP "${CMAKE_CURRENT_BINARY_DIR}/generated/embedded_kb.cpp")
add_custom_command(
  OUTPUT "${NEDEN_KB_CPP}"
  COMMAND "${CMAKE_COMMAND}" -DIN=${NEDEN_KB_JSON} -DOUT=${NEDEN_KB_CPP}
          -P "${PROJECT_SOURCE_DIR}/cmake/embed.cmake"
  DEPENDS "${NEDEN_KB_JSON}" "${PROJECT_SOURCE_DIR}/cmake/embed.cmake"
  COMMENT "Embedding runtimes.json"
  VERBATIM)

file(GLOB_RECURSE NEDEN_CORE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.h")
file(GLOB_RECURSE NEDEN_CORE_HEADERS CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h")

add_library(neden_core STATIC ${NEDEN_CORE_SOURCES} ${NEDEN_CORE_HEADERS} "${NEDEN_KB_CPP}")
target_include_directories(neden_core PUBLIC include PRIVATE src)
target_compile_definitions(neden_core PRIVATE NEDEN_VERSION="${PROJECT_VERSION}")
target_link_libraries(neden_core PUBLIC advapi32 shlwapi wintrust crypt32 winhttp)
