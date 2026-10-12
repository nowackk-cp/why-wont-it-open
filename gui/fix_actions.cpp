#include "fix_actions.h"

namespace gui::fixes {

bool winget_available() { return neden::fix::winget_available(); }

neden::fix::Outcome install_with_winget(const std::string& winget_id) {
  return neden::fix::install_with_winget(winget_id);
}

neden::fix::Outcome download_and_install(const std::string& url, const std::string& expected_signer,
                                         const std::function<bool(int percent)>& on_progress) {
  return neden::fix::download_verify_run(
      url, expected_signer, [&](std::uint64_t received, std::uint64_t total) {
        const int percent = total ? static_cast<int>(received * 100 / total) : -1;
        return on_progress ? on_progress(percent) : true;
      });
}

std::string url_host(const std::string& url) {
  const std::string scheme = "https://";
  if (url.compare(0, scheme.size(), scheme) != 0) return {};
  const size_t end = url.find_first_of("/?#", scheme.size());
  return url.substr(scheme.size(), end == std::string::npos ? std::string::npos : end - scheme.size());
}

}  // namespace gui::fixes
