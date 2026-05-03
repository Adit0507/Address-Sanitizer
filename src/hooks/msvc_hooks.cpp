#include "msvc_hooks.h"
#include "asan_config.h"
#include <atomic>

static thread_local int tl_call_depth = 0; // thread local call depth one counter per thread
static std::atomic<int> g_max_depth{0};

extern "C" void penter_handler()
{
    ++tl_call_depth;

    int cur = tl_call_depth;
    int old = g_max_depth.load(std::memory_order_relaxed);
    while (cur > old && !g_max_depth.compare_exchange_weak(old, cur, std::memory_order_relaxed))
    {
    }
}

extern "C" void pexit_handler()
{
    if (tl_call_depth > 0)
        --tl_call_depth;
}

int asan_call_depth()
{
    return tl_call_depth;
}

void asan_reset_call_depth()
{
    tl_call_depth = 0;
}