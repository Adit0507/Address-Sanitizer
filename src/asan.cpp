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

void asan_shutdown() {
    if(!g_initialized.load()) return;

    get_quarantine().flush();   //releasin held memory
    report_summary();
    get_shadow_memory().shutdown();//release shadow memory reservation
    symbols_shutdown(); //clean up dbgehlp

    g_initialized.store(false);
}

void asan_check(uintptr_t addr, size_t size, bool is_write) {
    if(!g_initialized.load(std:: memory_order_relaxed)) return;

    __asan_check(addr, size, is_write);
}

void *asan_malloc(size_t size) {
    return get_heap_tracker().on_malloc(size);
}
void *asan_calloc(size_t count, size_t size) {
    return get_heap_tracker().on_calloc(count, size);
}
void *asan_realloc(void *ptr, size_t new_size){

}
void asan_free(void *ptr) {
    get_heap_tracker().on_free(ptr);
}