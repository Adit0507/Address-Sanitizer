#include "win32_symbols.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "DbgHelp.lib")

#include <cstdio>
#include <cstring>
#include <mutex>

static std::mutex g_sym_mutex;
static bool g_initialised = false;

bool symbols_init()
{
    std::lock_guard<std::mutex> lock(g_sym_mutex);
    if (g_initialised)
        return true;

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    g_initialised = SymInitialize(GetCurrentProcess(), nullptr, TRUE) != FALSE;
    if (!g_initialised)
    {
        fprintf(stderr, "[asan] DbgHelp SymInitialize failed: %lu\n", GetLastError());
    }

    return g_initialised;
}