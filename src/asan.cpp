#include "../include/asan.h"
#include "runtime/shadow_memory.h"
#include "runtime/heap_tracker.h"
#include "runtime/quarantine.h"
#include "runtime/checker.h"
#include "reporting/error_reporter.h"
#include "reporting/stack_trace.h"
#include "platform/win32_symbols.h"
#include "hooks/msvc_hooks.h"

#include <cstdio>
#include <atomic>

static std::atomic<bool> g_initialized{false};

void asan_init()
{
    if (g_initialized.exchange(true))
        return;

    init_symbol_handler();
    if (!get_shadow_memory().init())
    {
        fprintf(stderr, "asan FATAL: Shadow memory init failed. Aborting\n");
        abort();
    }

    asan_reset_call_depth();
    fprintf(stderr, "[my_asan] Initialised. Redzone: %d bytes, "
                    "Quarantine: %llu MB\n",
            ASAN_REDZONE_SIZE, static_cast<unsigned long long>(ASAN_QUARANTINE_MAX_BYTES) / (1024 * 1024));
}