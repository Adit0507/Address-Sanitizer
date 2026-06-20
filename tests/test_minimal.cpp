// tests/test_minimal.cpp
#include <cstdio>
#include <cstdlib>

// forward declare just asan_init/shutdown
void asan_init();
void asan_shutdown();

int main()
{
    printf("step 1: main reached\n"); fflush(stdout);

    printf("step 2: calling asan_init...\n"); fflush(stdout);
    asan_init();

    printf("step 3: asan_init done\n"); fflush(stdout);

    asan_shutdown();

    printf("step 4: done\n"); fflush(stdout);
    return 0;
}