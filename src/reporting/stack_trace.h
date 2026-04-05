#pragma once

#ifndef ASAN_STACK_TRACE_h
#define ASAN_STACK_TRACE_h

#include "asan_types.h"
#include <cstdio>

bool init_symbol_handler();

// capturin upto maxframes into trace
void capture_stack_trace(StackTrace &trace, int max_frames, int frames_to_skip = 2);

struct FrameInfo // symbol info for one frame
{
    void *address;
    char function[256];
    char filename[512];
    int line;
    bool resolved;
};

FrameInfo resolve_frame(void *address);

void print_stack_trace(FILE *out, const StackTrace &trace, const char *ident = "    ");

#endif