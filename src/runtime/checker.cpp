#include "checker.h"
#include "shadow_memory.h"
#include "heap_tracker.h"
#include "../reporting/error_reporter.h"
#include "../reporting/stack_trace.h"
#include "asan_types.h"
#include "asan_config.h"

// classifying error from shadow byte+ heap tracker
static ErrorType classify_error(uintptr_t addr, uint8_t shadow_byte)
{
    AllocInfo info;

    switch (shadow_byte)
    {
    case shadow::kHeapLeftRedZone:
    case shadow::kHeapRightRedZone:
        return ErrorType::HeapBufferOverflow;
    case shadow::kFreedMemory:
        return ErrorType::UseAfterFree;
    case shadow::kStackRedzone:
        return ErrorType::StackBufferOverflow;

    default:
        if (shadow_byte >= 0x01 && shadow_byte <= 0x07)
        {
            return ErrorType::HeapBufferOverflow;
        }

        if (get_heap_tracker().find_allocation_for_addr(addr, info))
        {
            if (info.is_freed)
                return ErrorType::UseAfterFree;
            if (addr < info.user_ptr)
                return ErrorType::HeapBufferUnderflow;

            return ErrorType::HeapBufferOverflow;
        }

        return ErrorType::Unknown;
    }
}

void __asan_check(uintptr_t addr, size_t size, bool is_write)
{
    ShadowMemory &shadow = get_shadow_memory();
    if (!shadow.is_initialized())
        return;

    if (!shadow.is_poisoned(addr, size))
        return; // checkin first bytes shadow

    uint8_t shadow_byte = shadow.get_shadow_byte(addr);    
    AsanReport report;
    report.fault_addr = addr;
    report.access_size = size;
    report.is_write = is_write;
    report.shadow_byte = shadow_byte;
    report.error_type = classify_error(addr, shadow_byte);

    capture_stack_trace(report.access_trace, ASAN_MAX_STACK_FRAMES);

    get_heap_tracker().find_allocation_for_addr(addr, report.alloc_info); //attaching allocation metadata if we can find related allociton

    report_error(report);
}

void __asan_check_load(uintptr_t addr, size_t size)
{
    __asan_check(addr, size, false);
}
void __asan_check_store(uintptr_t addr, size_t size)
{
    __asan_check(addr, size, true);
}