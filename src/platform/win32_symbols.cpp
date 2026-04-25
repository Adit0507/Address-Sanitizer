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

ResolvedSymbol symbols_resolve(uintptr_t address)
{
    ResolvedSymbol result{};
    result.valid = false;
    result.line = 0;

    if (!address)
    {
        strncpy_s(result.name, sizeof(result.name), "<null>", _TRUNCATE);
        return result;
    }

    std::lock_guard<std::mutex> lock(g_sym_mutex);
    if (!g_initialised)
    {
        snprintf(result.name, sizeof(result.name), "0x%016llx", static_cast<unsigned long long>(address));

        return result;
    }

    HANDLE process = GetCurrentProcess();

    // resolvin name
    alignas(SYMBOL_INFO) char buf[sizeof(SYMBOL_INFO) + 256] = {};
    SYMBOL_INFO *sym = reinterpret_cast<SYMBOL_INFO *>(buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = 255;

    DWORD64 disp = 0;
    if (SymFromAddr(process, static_cast<DWORD64>(address), &disp, sym))
    {
        strncpy_s(result.name, sizeof(result.name), sym->Name, _TRUNCATE);
        result.valid = true;
    }else {
        snprintf(result.name, sizeof(result.name), "0x%016llx", static_cast<unsigned long long>(address));
    }

    // resolvin line
    IMAGEHLP_LINE64 line {};
    line.SizeOfStruct = sizeof(line);
    DWORD line_disp =0;
    if(SymGetLineFromAddr64(process, static_cast<DWORD64>(address), &line_disp, &line)){
        strncpy_s(result.filename, sizeof(result.filename), line.FileName, _TRUNCATE);
        result.line= static_cast<int>(line.LineNumber);
    }

    return result;
}

void symbols_shutdown()
{
    std::lock_guard<std::mutex> lock(g_sym_mutex);

    if (g_initialised)
    {
        SymCleanup(GetCurrentProcess());
        g_initialised = false;
    }
}