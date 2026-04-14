#include "error_reporter.h"
#include "console_output.h"
#include "stack_trace.h"
#include "../runtime/shadow_memory.h"
#include "asan_config.h"

#include <cstdio>
#include <cstdlib>
#include <atomic>
#include <mutex>

static std::atomic<int> g_error_count{0};
static std::mutex g_report_mutex; // serialise concurrent reports

static const char *error_type_string(ErrorType t)
{
    switch (t)
    {
    case ErrorType::HeapBufferOverflow:
        return "heap-buffer-overflow";
    case ErrorType::HeapBufferUnderflow:
        return "heap-buffer-underflow";
    case ErrorType::UseAfterFree:
        return "heap-use-after-free";
    case ErrorType::DoubleFree:
        return "double-free";
    case ErrorType::InvalidFree:
        return "invalid-free";
    case ErrorType::StackBufferOverflow:
        return "stack-buffer-overflow";
    case ErrorType::UseAfterReturn:
        return "stack-use-after-return";

    default:
        return "unknown error";
    }
}