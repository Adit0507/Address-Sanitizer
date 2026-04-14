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

static void print_access_info(const AsanReport &r)
{
    cprint(ConsoleColor::White, "\n  %s of size %zu at address 0x%016llx\n", r.is_write ? "WRITE" : "READ", r.access_size, static_cast<unsigned long long>(r.fault_addr));

    cprint(ConsoleColor::Gray, "  Shadow byte at fault address: 0x%02X\n", r.shadow_byte);
}
static void print_alloc_section(const AllocInfo &info)
{
    if (info.user_ptr == 0)
        return;
    if (info.is_freed)
    {
        cprint(ConsoleColor::Cyan, "\n  Freed region of %zu bytes [0x%016llx, 0x%016llx)\n", info.user_size, static_cast<unsigned long long>(info.user_ptr), static_cast<unsigned long long>(info.user_ptr + info.user_size));

        cprint(ConsoleColor::Cyan, "\n  freed here:\n");
        print_stack_trace(stderr, info.free_trace);
    }

    cprint(ConsoleColor::Green, "\n  Allocated %zu bytes at [0x%016llx, 0x%016llx)\n", info.user_size, static_cast<unsigned long long>(info.user_ptr), static_cast<unsigned long long>(info.user_ptr + info.user_size));

    cprint(ConsoleColor::Green, "\n  allocated here:\n");

    print_stack_trace(stderr, info.alloc_trace);
}
