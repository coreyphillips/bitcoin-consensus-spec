// Definitions for the symbols declared in Core's util/check.h.
//
// Core defines them in util/check.cpp, which needs the generated bitcoin-build-config.h and
// clientversion.cpp only to print the client name and version in an "internal bug" message.
// These definitions behave the same way (print and abort, or throw NonFatalCheckError) without
// that version banner. They are only reached if Core's own assertions fail.

#include <util/check.h>

#include <tinyformat.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <string>
#include <string_view>

std::string StrFormatInternalBug(std::string_view msg, const std::source_location& loc)
{
    return strprintf("Internal bug detected: %s\n%s:%d (%s)\n"
                     "oracle-core (Bitcoin Core v32.1 consensus code)\n",
                     msg, loc.file_name(), loc.line(), loc.function_name());
}

NonFatalCheckError::NonFatalCheckError(std::string_view msg, const std::source_location& loc)
    : std::runtime_error{StrFormatInternalBug(msg, loc)}
{
}

bool g_detail_test_only_CheckFailuresAreExceptionsNotAborts{false};

void assertion_fail(const std::source_location& loc, std::string_view assertion)
{
    if (g_detail_test_only_CheckFailuresAreExceptionsNotAborts) {
        throw NonFatalCheckError{assertion, loc};
    }
    auto str = strprintf("%s:%s %s: Assertion `%s' failed.\n", loc.file_name(), loc.line(), loc.function_name(), assertion);
    fwrite(str.data(), 1, str.size(), stderr);
    std::abort();
}

std::atomic<bool> g_enable_dynamic_fuzz_determinism{false};
