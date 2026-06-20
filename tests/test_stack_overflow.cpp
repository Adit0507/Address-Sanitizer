#include "../include/asan.h"
#include <cstdio>

int main()
{
    asan_init();

    struct
    {
        char buf[16];
        char guard[8];
    } stack_frame;

    fprintf(stderr, "[test] Poisoning stack guard region...\n");
    asan_poison(stack_frame.guard, sizeof(stack_frame.guard), ASAN_POISON_STACK_REDZONE);

    fprintf(stderr, "[test] Writing into poisoned guard...\n");
    CHECK_WRITE(stack_frame.guard, sizeof(int)); 

    stack_frame.guard[0] = 0x42; 

    asan_unpoison(stack_frame.guard, sizeof(stack_frame.guard));
    asan_shutdown();
    return 0;
}