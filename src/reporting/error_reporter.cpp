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

void report_error(const AsanReport &report)
{
    std::lock_guard<std::mutex> lock(g_report_mutex);
    g_error_count.fetch_add(1, std::memory_order_relaxed);

    const char *kind = error_type_string(report.error_type);

    print_asan_header(kind);
    print_access_info(report);

    cprint(ConsoleColor::Yellow, "\n Access stack trace: \n");
    print_stack_trace(stderr, report.access_trace);
    print_alloc_section(report.alloc_info);

#if ASAN_PRINT_SHADOW_CONTEXT
    get_shadow_memory().dump_shadow_region(report.fault_addr, ASAN_SHADOW_CONTEXT_BYTES);
#endif

    print_divider();
    fprintf(stderr, "\n");
    fflush(stderr);

#if ASAN_ABORT_ON_ERROR
    abort();
#endif
}

void report_double_free(uintptr_t ptr, const AllocInfo &prev)
{
    std::lock_guard<std::mutex> lock(g_report_mutex);
    g_error_count.fetch_add(1, std::memory_order_relaxed);

    print_asan_header("double-free");

    cprint(ConsoleColor::White, "\n  double-free of pointer 0x%016llx\n", static_cast<unsigned long long>(ptr));

    cprint(ConsoleColor::Cyan, "\n  previously freed here:\n");
    print_stack_trace(stderr, prev.free_trace);

    cprint(ConsoleColor::Green, "\n  originally allocated here:\n");
    print_stack_trace(stderr, prev.alloc_trace);

    print_divider();
    fflush(stderr);

#if ASAN_ABORT_ON_ERROR
    abort();
#endif
}

void report_invalid_free(uintptr_t ptr)
{
    std::lock_guard<std::mutex> lock(g_report_mutex);
    g_error_count.fetch_add(1, std::memory_order_relaxed);

    print_asan_header("invalid-free");

    cprint(ConsoleColor::White, "\n  free() called on unknown pointer 0x%016llx\n"
                                "  (not a heap allocation, or pointer was offset from original)\n",
           static_cast<unsigned long long>(ptr));

    StackTrace trace;
    capture_stack_trace(trace, ASAN_MAX_STACK_FRAMES);
    cprint(ConsoleColor::Yellow, "\n  free() called here:\n");
    print_stack_trace(stderr, trace);

    print_divider();
    fflush(stderr);

#if ASAN_ABORT_ON_ERROR
    abort();
#endif
}

void report_summary()
{
    int count = g_error_count.load(std::memory_order_relaxed);

    fprintf(stderr, "\n");
    print_divider();
    if (count == 0)
    {
        cprint(ConsoleColor::Green, "asan: No errors detected.\n");
    }
    else
    {
        cprint(ConsoleColor::BrightRed, "asan: %d error(s) detected.\n", count);
    }
    print_divider();
    fprintf(stderr, "\n");
}

int get_error_count()
{
    return g_error_count.load(std::memory_order_relaxed);
}
