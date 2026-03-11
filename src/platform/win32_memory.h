#pragma once

#ifndef ASAN_WIN32_MEMORY_H
#define ASAN_WIN32_MEMORY_H

#include <cstddef>
#include <cstdint>

void *platform_reserve(size_t size); // resevre region of virtual address space

void *platform_commit(void *base, size_t size); //committin sub range of previously reserved region

void platform_release(void *base);  //release entire reserved region

size_t platform_page_size();    //system page size
size_t platform_alloc_granularity();   //returns system allocation granularity
bool platform_is_committed(void *addr, size_t size);    //query whether given address range is committed mmemory

#endif