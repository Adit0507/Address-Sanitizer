#include "stack_trace.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "DbgHelp.lib")

#include <cstdio>
#include <cstring>
#include <mutex>

static std::mutex g_dbghelp_mutex;
static bool g_symbols_ready = false;

bool init_symbol_handler()
{
    std::lock_guard<std::mutex> lock(g_dbghelp_mutex);
    if (g_symbols_ready)
        return true;
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);

    if (!SymInitialize(GetCurrentProcess(), nullptr, TRUE))
    {
        fprintf(stderr, "[my_asan] WARNING: SymInitialize failed (%lu). "
                        "Stack traces will show raw addresses.\n",
                GetLastError());
        return false;
    }

    g_symbols_ready = true;

    return true;
}