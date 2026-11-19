// The logging hooks Core's kernel/chainparams.cpp links against.
//
// util/log.h leaves util::log::Log to the application. Core's own definition (logging.cpp) and
// util/threadnames.cpp would pull in the logger and the generated bitcoin-build-config.h. The only
// log call in chainparams.cpp is for a signet with a custom challenge, which the oracle never
// builds, so these write the message to standard error and nothing more.

#include <util/log.h>
#include <util/threadnames.h>

#include <cstdio>
#include <string>

namespace util {
std::string ThreadGetInternalName() { return {}; }

namespace log {
void Log(Entry entry)
{
    std::fwrite(entry.message.data(), 1, entry.message.size(), stderr);
}
} // namespace log
} // namespace util
