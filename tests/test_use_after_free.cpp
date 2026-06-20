#include "asan.h"
#include <cstdio>

int main()
{
    asan_init();

    int *p = SAFE_MALLOC(int, 4);
    p[0] = 42;

    fprintf(stderr, "[test] Freeng p...\n");
    SAFE_FREE(p);
    fprintf(stderr, "[test] reading p[0] after free...\n");
    CHECK_READ(p, sizeof(int));

    volatile int val = p[0];    //continues to use the pointer after the memory it points to has been deallocated
    (void)val;

    asan_shutdown();
    return 0;
}