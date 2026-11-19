// The logging hooks Core's kernel/chainparams.cpp and signet.cpp link against.
//
// util/log.h leaves these to the application. Core's own definitions (logging.cpp) and
// util/threadnames.cpp would pull in the logger and the generated bitcoin-build-config.h. The only
// log calls on the oracle's paths are chainparams.cpp's line for every signet with a custom
// challenge (one per `signet_check` request) and signet.cpp's debug lines, which say no more than
// the answer does. So nothing is logged.

#include <util/log.h>
#include <util/threadnames.h>

#include <string>

namespace util {
std::string ThreadGetInternalName() { return {}; }

namespace log {
void Log(Entry) {}
bool ShouldDebugLog(Category) { return false; }
bool ShouldTraceLog(Category) { return false; }
} // namespace log
} // namespace util
