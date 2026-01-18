#include "asan_report.h"
#include "asan_shadow.h"
#include <iostream>
#include <iomanip>
#include <cstdlib>
#ifdef _WIN32
  // no execinfo on Windows
#else
  #include <execinfo.h>
#endif


namespace miniasan
{
    ErrorReporter &ErrorReporter::getInstance()
    {
        static ErrorReporter instance;

        return instance;
    }

    const char *ErrorReporter::shadowByteToDescription(int8_t value)
    {
        if (value == 0)
            return "heap accessible";
        if (value > 0 && value < 8)
            return "partially accessible";

        switch (value)
        {
        case kAsanHeapLeftRedzoneMagic:
            return "heap left redzone";
        case kAsanHeapRightRedzoneMagic:
            return "heap right redzone";
        case kAsanHeapFreeMagic:
            return "heap freed memory";
        case kAsanStackRedzoneMagic:
            return "stack redzone";
        default:
            return "unknown";
        }
    }

    void ErrorReporter::printStackTrace(void **stack, size_t size, const char *label)
    {
#ifndef _WIN32
        if (size == 0)
            return;

        std::cerr << label << ":\n";
        char **symbols = backtrace_symbols(stack, size);
        for (size_t i = 0; i < size; i++)
        {
            std::cerr << "    #" << i << " " << symbols[i] << "\n";
        }
        ::free(symbols);
#else
        std::cerr << label << ": <stack trace not supported on Windows>\n";
#endif
    }

    void ErrorReporter::printShadowBytes(void *addr, size_t range)
    {
        std::cerr << "\nShadow bytes around the buggy address:\n";

        uintptr_t base_addr = (uintptr_t)addr;
        uintptr_t shadow_start = (base_addr >> SHADOW_SCALE) - 8;

        for (int i = -8; i <= 8; i++)
        {
            uintptr_t shadow_addr = shadow_start + i;
            int8_t *shadow_ptr = ShadowMemory::getInstance().getShadowAddress(base_addr) + i;
            int8_t value = *shadow_ptr;

            std::cerr << "  0x" << std::hex << std::setw(16) << std::setfill('0') << (shadow_addr << SHADOW_SCALE) << ": ";

            if (i == 0)
                std::cerr << "=>";
            else
                std::cerr << "  ";

            std::cerr << std::hex << std::setw(2) << (int)(unsigned char)value << " (" << shadowByteToDescription(value) << ")\n";
        }
        std::cerr << std::dec;
    }

    void ErrorReporter::reportMemoryError(void *addr, size_t size)
    {
        std::cerr << "\n";
        std::cerr << "=================================================================\n";
        std::cerr << "==ERROR: AddressSanitizer: heap-buffer-overflow\n";
        std::cerr << "==Access of size " << size << " at address " << addr << "\n";

        void *stack[16];
        size_t stack_size = captureStack(stack, 16);
        printStackTrace(stack, stack_size, "READ of size");

        printShadowBytes(addr, 64);

        std::cerr << "=================================================================\n";
        std::cerr << std::flush;

        abort();
    }
    void ErrorReporter::reportInvalidFree(void* ptr) {
    std::cerr << "\n";
    std::cerr << "=================================================================\n";
    std::cerr << "==ERROR: AddressSanitizer: attempting to free invalid pointer\n";
    std::cerr << "==Address: " << ptr << "\n";
    
    void* stack[16];
    size_t stack_size = captureStack(stack, 16);
    printStackTrace(stack, stack_size, "Invalid free");
    
    std::cerr << "=================================================================\n";
    std::cerr << std::flush;
    
    abort();
}

void ErrorReporter::reportDoubleFree(void* ptr, AllocationMetaData* metadata) {
    std::cerr << "\n";
    std::cerr << "=================================================================\n";
    std::cerr << "==ERROR: AddressSanitizer: attempting free on address which was already freed\n";
    std::cerr << "==Address: " << ptr << "\n";
    std::cerr << "==Original allocation size: " << metadata->user_size << "\n";
    
    void* stack[16];
    size_t stack_size = captureStack(stack, 16);
    printStackTrace(stack, stack_size, "Current free");
    
    printStackTrace(metadata->alloc_stack, metadata->alloc_stack_size, "Previously allocated");
    printStackTrace(metadata->free_stack, metadata->free_stack_size, "Previously freed");
    
    std::cerr << "=================================================================\n";
    std::cerr << std::flush;
    
    abort();
}

void ErrorReporter::reportUseAfterFree(void* ptr, AllocationMetaData* metadata) {
    std::cerr << "\n";
    std::cerr << "=================================================================\n";
    std::cerr << "==ERROR: AddressSanitizer: heap-use-after-free\n";
    std::cerr << "==Address: " << ptr << "\n";
    
    printStackTrace(metadata->alloc_stack, metadata->alloc_stack_size, "Allocated");
    printStackTrace(metadata->free_stack, metadata->free_stack_size, "Freed");
    
    printShadowBytes(ptr, 64);
    
    std::cerr << "=================================================================\n";
    std::cerr << std::flush;
    
    abort();
}


}
