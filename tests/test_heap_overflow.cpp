#include "asan.h"
#include <cstdio>

int main()
{
    asan_init();

    fprintf(stderr, "Allocating int[10]...\n");
    int* p = SAFE_MALLOC(int, 10);

    fprintf(stderr, "Writing to p[10] (one past end)...\n");
    CHECK_WRITE(&p[10], sizeof(int));

    p[10] = 0xDEADBEEF;

    SAFE_FREE(p);
    asan_shutdown();
    return 0;
}