#include "asan.h"
#include <cstdio>
#include <cstring>

int main()
{
    asan_init();

    fprintf(stderr, "[test] All accessses should be clean... \n");

    // valid heap alloation and access
    int *arr = SAFE_MALLOC(int, 16);
    for (int i = 0; i < 16; i++)
    {
        CHECK_WRITE(&arr[i], sizeof(int));
        arr[i] = i * 2;
    }
    for (int i = 0; i < 16; i++)
    {
        CHECK_READ(&arr[i], sizeof(int));
        fprintf(stderr, "  arr[%d] = %d\n", i, arr[i]);
    }
    SAFE_FREE(arr);

    // valid calloc
    char *buf = SAFE_CALLOC(char, 64);
    CHECK_WRITE(buf, 64);
    memset(buf, 'A', 64);
    SAFE_FREE(buf);

    // valid realloc
    int *p = SAFE_MALLOC(int, 4);
    p[0] = 99;
    p = static_cast<int *>(asan_realloc(p, sizeof(int) * 8));
    CHECK_READ(p, sizeof(int));
    fprintf(stderr, " realloc p[0]= %d\n", p[0]);
    fprintf(stderr, "about to free p = %p\n", p);
    fflush(stderr);
    SAFE_FREE(p);
    fprintf(stderr, "freed p successfully\n");
    fflush(stderr);
    
    asan_shutdown();
    return 0;
}