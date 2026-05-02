#pragma once

// hot path memory access validator
#ifndef ASAN_CHECKER_H
#define ASAN_CHECKER_H

#include <cstdint>
#include <cstddef>

void __asan_check_load(uintptr_t addr, size_t size);    //called before memory read of size bytes at addr
void __asan_check_store(uintptr_t addr, size_t size);   //called before memory write of size bytes at addr
void __asan_check(uintptr_t addr, size_t size, bool is_write);  //entry point for asan_check for public api

#endif