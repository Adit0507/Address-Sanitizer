#include "console_output.h"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cstring>

static constexpr WORD kColorDefault = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD kColorRed = FOREGROUND_RED;
static constexpr WORD kColorBrightRed = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD kColorYellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD kColorGreen = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD kColorCyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD kColorWhite = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD kColorGray = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

static HANDLE stderr_handle()
{
    static HANDLE h = GetStdHandle(STD_ERROR_HANDLE);
    return h;
}
static bool is_console()
{
    DWORD mode = 0;

    return GetConsoleMode(stderr_handle(), &mode) != 0;
}

void set_color(ConsoleColor color)
{
    if (!is_console)
        return;

    WORD attr = kColorDefault;
    switch (color)
    {
    case ConsoleColor::Red:
        attr = kColorRed;
        break;

    case ConsoleColor::BrightRed:
        attr = kColorBrightRed;
        break;
    case ConsoleColor::Yellow:
        attr = kColorYellow;
        break;
    case ConsoleColor::Green:
        attr = kColorGreen;
        break;
    case ConsoleColor::Cyan:
        attr = kColorCyan;
        break;
    case ConsoleColor::White:
        attr = kColorWhite;
        break;
    case ConsoleColor::Gray:
        attr = kColorGray;
        break;
    default:
        attr = kColorDefault;
        break;
    }

    SetConsoleTextAttribute(stderr_handle(), attr);
}

void reset_color()
{
    set_color(ConsoleColor::Default);
}

void cprint(ConsoleColor color, const char *fmt, ...)
{
    set_color(color);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);

    reset_color();
}

void print_asan_header(const char *error_kind)
{
    fprintf(stderr, "\n");
    cprint(ConsoleColor::BrightRed, "asan: ERROR: %s\n", error_kind);
}

void print_divider()
{
    cprint(ConsoleColor::Gray,
           "================================================================\n");
}
