#include "stack_trace.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#pragma comment(lib, "DbgHelp.lib")

#include <cstdio>
#include <cstring>
#include <mutex>

static CRITICAL_SECTION cs_;
static bool g_symbols_ready = false;
static bool g_cs_initialized = false;

struct CSLock
{
    CRITICAL_SECTION &cs;
    CSLock(CRITICAL_SECTION &c) : cs(c) { EnterCriticalSection(&cs); }
    ~CSLock() { LeaveCriticalSection(&cs); }
};

bool init_symbol_handler()
{
    if(!g_cs_initialized){
        InitializeCriticalSection(&cs_);
        g_cs_initialized = true;
    }

    CSLock lock(cs_);
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

void capture_stack_trace(StackTrace &trace, int max_frames, int frames_to_skip)
{
    if (max_frames > kMaxStackFrame)
        max_frames = kMaxStackFrame;
    // frames to skip capturestackbacktrace itself +this function
    USHORT captured = CaptureStackBackTrace(static_cast<ULONG>(frames_to_skip), static_cast<ULONG>(max_frames), trace.frames, nullptr);

    trace.depth = static_cast<int>(captured);
}

FrameInfo resolve_frame(void *address)
{
    FrameInfo fi{};

    fi.address = address;
    fi.resolved = false;
    fi.line = 0;
    fi.function[0] = '\0';
    fi.filename[0] = '\0';

    if (!g_symbols_ready)
    {
        snprintf(fi.function, sizeof(fi.function), "%p", address);
        return fi;
    }

    CSLock lock(cs_);

    HANDLE process = GetCurrentProcess();

    // symbol info needs extra space after it for the name string
    constexpr size_t kNameLen = 255;
    alignas(SYMBOL_INFO) char sym_buf[sizeof(SYMBOL_INFO) + kNameLen + 1] = {};
    SYMBOL_INFO *sym = reinterpret_cast<SYMBOL_INFO *>(sym_buf);
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = kNameLen;

    DWORD64 displacement = 0;
    if (SymFromAddr(process, reinterpret_cast<DWORD64>(address), &displacement, sym))
    {
        strncpy_s(fi.function, sizeof(fi.function), sym->Name, _TRUNCATE);

        fi.resolved = true;
    }
    else
    {
        snprintf(fi.function, sizeof(fi.function), "0x%p", address);
    }

    // file and line
    IMAGEHLP_LINE64 line_info{};
    line_info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);
    DWORD line_displacement = 0;

    if (SymGetLineFromAddr64(process, reinterpret_cast<DWORD64>(address), &line_displacement, &line_info))
    {
        strncpy_s(fi.filename, sizeof(fi.filename), line_info.FileName, _TRUNCATE);
        fi.line = static_cast<int>(line_info.LineNumber);
    }

    return fi;
}

// cleanup func
void cleanup_symbol_handler() {
    if(g_cs_initialized){
        DeleteCriticalSection(&cs_);
        g_cs_initialized = false;
    }
}

void print_stack_trace(FILE *out, const StackTrace &trace, const char *indent)
{
    if (trace.depth == 0)
    {
        fprintf(out, "%s<no stack trace available>\n", indent);
        return;
    }

    for (int i = 0; i < trace.depth; i++)
    {
        FrameInfo fi = resolve_frame(trace.frames[i]);
        if (fi.filename[0] != '\0')
        {
            fprintf(out, "%s#%-2d  %s  (%s:%d)\n", indent, i, fi.function, fi.filename, fi.line);
        }
        else
        {
            fprintf(out, "%s#%-2d  %s\n", indent, i, fi.function);
        }
    }
}