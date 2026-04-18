#pragma once

#ifndef ASAN_CONSOLE_OUTPUT_H
#define ASAN_CONSOLE_OUTPUT_H

#include <cstdio>

enum class ConsoleColor {
    Default,
    Red,
    BrightRed,
    Yellow,
    Green,
    Cyan,
    White,
    Gray,
};

void set_color(ConsoleColor color);
 
void reset_color();
 
void cprint(ConsoleColor color, const char* fmt, ...);
 
void print_asan_header(const char* error_kind);
void print_divider();
 
#endif