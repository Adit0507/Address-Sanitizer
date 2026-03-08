#include "shadow_memory.h"
#include "../platform/win32_memory.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <algorithm>

bool ShadowMemory ::init()
{
    if (shadow_base_ != nullptr)
        return true;

    void *base = platform_reserve(shadow::kShadowSize);
    if (!base)
    {
        fprintf(stderr, "[asan] FATAL: Failed to reserve %.0f TB shadow region.\n", static_cast<double>(shadow::kShadowSize) / (1ULL << 40));
        return false;
    }

    shadow_base_ = base;
    committed_end_ = 0;

    fprintf(stderr, "[asan] Shadow memory initialised. Base %p, size: 16TB\n", shadow_base_);

    return true;
}

void ShadowMemory::shutdown()
{
    if (shadow_base_ == nullptr)
        return;
    platform_release(shadow_base_);
    shadow_base_ = nullptr;
    committed_end_ = 0;
}

ShadowMemory::~ShadowMemory()
{
    shutdown();
}