// Thin wrapper over neden/fix.h so the GUI has exactly one place that talks to it.
#pragma once

#include <functional>
#include <string>

#include "neden/fix.h"

namespace gui::fixes {

bool winget_available();
neden::fix::Outcome install_with_winget(const std::string& winget_id);
// percent is -1 when the total size is unknown. Return false from the callback to cancel.
neden::fix::Outcome download_and_install(const std::string& url, const std::string& expected_signer,
                                         const std::function<bool(int percent)>& on_progress);
// Host part of an https URL ("download.microsoft.com"), for the confirmation text.
std::string url_host(const std::string& url);

}  // namespace gui::fixes
