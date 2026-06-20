#include "quarantine.h"
#include "shadow_memory.h"
#include "asan_config.h"

#include <cstdlib>
#include <cassert>
#include <cstdio>

Quarantine::Quarantine(size_t max_bytes) : head_(nullptr), tail_(nullptr), total_bytes_(0), count_(0), max_bytes_(max_bytes) {}
Quarantine::~Quarantine()
{
    flush();
}

void Quarantine::enqueue(const AllocInfo &info)
{
    ShadowMemory &shadow = get_shadow_memory();
    // poison the user region so access is caught
    shadow.poison_partial(info.user_ptr, info.user_size, shadow::kFreedMemory);

    // heap allocated metadata node
    QuarantineEntry *entry = static_cast<QuarantineEntry*>(::malloc(sizeof(QuarantineEntry)));
    if(!entry) return;

    entry->alloc_ptr = info.alloc_ptr;
    entry->user_ptr = info.user_ptr;
    entry->alloc_size = info.alloc_size;
    entry->user_size = info.user_size;
    entry->free_trace = info.free_trace;
    entry->next = nullptr;

    if (tail_ == nullptr)
    {
        head_ = tail_ = entry;
    }
    else
    {
        tail_->next = entry;
        tail_ = entry;
    }

    total_bytes_ += info.alloc_size;
    ++count_;

    drain_to_limit(); // drain oldest entries if over size limit
}

void Quarantine::flush()
{
    while (head_ != nullptr)
    {
        QuarantineEntry *next = head_->next;
        release_entry(head_);
        head_ = next;
    }

    tail_ = nullptr;
    total_bytes_ = 0;
    count_ = 0;
}

void Quarantine::drain_to_limit()
{
    while (total_bytes_ > max_bytes_ && head_ != nullptr)
    {
        QuarantineEntry *oldest = head_;
        head_ = oldest->next;

        if (head_ == nullptr)
            tail_ = nullptr;
        total_bytes_ -= oldest->alloc_size;
        --count_;

        release_entry(oldest);
    }
}

void Quarantine::release_entry(QuarantineEntry *entry)
{
    ShadowMemory& shadow = get_shadow_memory();
 
    shadow.unpoison(entry->alloc_ptr, entry->alloc_size); //unpoison full allocation
 
    ::free(reinterpret_cast<void*>(entry->alloc_ptr)); //return underlying memory to crt
    ::free(entry);
}

Quarantine &get_quarantine()
{
    static Quarantine instance(ASAN_QUARANTINE_MAX_BYTES);
    return instance;
}