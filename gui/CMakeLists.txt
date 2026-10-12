# Win32 GUI. Pure Win32 + common controls; no third-party dependencies.
configure_file(app.rc.in "${CMAKE_CURRENT_BINARY_DIR}/app.rc" @ONLY)

add_executable(neden-gui WIN32
  main.cpp
  window.cpp
  results_view.cpp
  theme.cpp
  strings.cpp
  fix_actions.cpp
  shell_menu.cpp
  "${CMAKE_CURRENT_BINARY_DIR}/app.rc")
set_target_properties(neden-gui PROPERTIES OUTPUT_NAME "WhyWontItOpen")
target_include_directories(neden-gui PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(neden-gui PRIVATE neden_core
  comctl32 shell32 ole32 uxtheme dwmapi shlwapi user32 gdi32 advapi32 uuid)
# The manifest is embedded through app.rc; don't let the linker add a second one.
target_link_options(neden-gui PRIVATE /MANIFEST:NO)
