#include "asan_shadow.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace miniasan
{
  ShadowMemory &ShadowMemory ::getInstance()
  {
    static ShadowMemory instance;
    return instance;
  }

  ShadowMemory::ShadowMemory() : shadow_base_(nullptr), initialized_(false) {}
  ShadowMemory::~ShadowMemory()
  {
    if (!shadow_base_)
      return;

    VirtualFree(shadow_base_, 0, MEM_RELEASE);
  }

  void ShadowMemory::init()
  {
    if (initialized_)
      return;

    size_t shadow_size = 1ULL << 32;
    shadow_base_ = (int8_t *)VirtualAlloc(nullptr, shadow_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!shadow_base_)
    {
      std::cerr << "Failed to allocate shadow memory (VirtualAlloc)\n";
      std::exit(1);
    }

    memset(shadow_base_, kAsanHeapFreeMagic, shadow_size);
    initialized_ = true;
  }

}
