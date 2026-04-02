#pragma once

#ifndef ASAN_QUARANTINE_H
#define ASAN_QUARANTINE_H

#include "asan_types.h"
#include <cstddef>

struct QuarantineEntry
{
    uintptr_t alloc_ptr;
    uintptr_t user_ptr;
    size_t alloc_size; // total allocation size with redzones
    size_t user_size;
    StackTrace free_trace;
    QuarantineEntry *next; // singly linked list
    QuarantineEntry() : alloc_ptr(0), user_ptr(0), alloc_size(0), user_size(0), next(nullptr) {}
};

class Quarantine
{
public:
    explicit Quarantine(size_t max_bytes);
    ~Quarantine();

    Quarantine(const Quarantine &) = delete;
    Quarantine &operator=(const Quarantine &) = delete;

    void enqueue(const AllocInfo &info);
    void flush();//force release all quarantined blocks

    size_t total_bytes() const {return total_bytes_;}
    size_t count() const {return count_;}

private:
    void drain_to_limit();  //release oldest entres until total bytes is more than max bytes
    void release_entry(QuarantineEntry* entry);
    QuarantineEntry* head_;
    QuarantineEntry* tail_;
    size_t total_bytes_;
    size_t count_;
    size_t max_bytes;
};

Quarantine &get_quarantine();

#endif