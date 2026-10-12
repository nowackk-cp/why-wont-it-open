#include "neden/version.h"
#include "test.h"

TEST(version_is_semver_like) {
  CHECK(!neden::version().empty());
  CHECK(neden::version().find('.') != std::string_view::npos);
}
