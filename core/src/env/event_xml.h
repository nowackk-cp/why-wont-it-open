// Tolerant extraction of the few fields we need from an event's XML
// (EvtRenderEventXml output). Not a general XML parser.
#pragma once

#include <cstdint>
#include <string_view>

#include "neden/env.h"

namespace neden::env {

// Fills provider, id, time, data and names (channel is taken from <Channel> if present).
// Returns false if no EventID could be found.
bool parse_event_xml(std::string_view xml, EventRecord& out);

// "2026-10-07T13:52:01.4361128Z" -> FILETIME. 0 on failure.
std::uint64_t parse_system_time(std::string_view iso);

}  // namespace neden::env
