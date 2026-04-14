#pragma once

#ifndef ASAN_ERROR_REPORTER_H
#define ASAN_ERROR_REPORTER_H

#include "asan_types.h"
#include <cstdint>

void report_error(const AsanReport &report);

void report_double_free(uintptr_t ptr, const AllocInfo &prev_free_info);
void report_invalid_free(uintptr_t ptr);
void report_summary();

int get_error_count();

#endif