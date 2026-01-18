#include "asan_report.h"
#include "asan_shadow.h"
#include <iostream>
#include <iomanip>
// #include <execinfo.h>
#include <cstdlib>

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

}
