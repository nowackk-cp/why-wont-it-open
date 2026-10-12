// Optional "Why won't it open?" entry in the Explorer right-click menu of .exe
// and .dll files. Per-user (HKCU), no administrator rights needed.
#pragma once

namespace gui {

bool register_shell_menu();
bool unregister_shell_menu();

}  // namespace gui
