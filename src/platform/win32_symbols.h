#pragma once

#ifndef ASAN_WIN32_SYMBOLS_H
#define ASAN_WIN32_SYMBOLS_H

#include <cstdint>
#include <cstddef>

bool symbols_init();

struct ResolvedSymbol
{
    char name[256]; //demangled functin name
    char filename[512]; //source file path
    int line;
    bool valid;
};

ResolvedSymbol symbols_resolve(uintptr_t address); 
void symbols_shutdown();

#endif