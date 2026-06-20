#define ASAN_REDZONE_SIZE 64
#define ASAN_ABORT_ON_ERROR

#include "asan.h"
#include <cstdio>

static void example_valid()
{ // valid usage
    fprintf(stderr, "\n Ex1. Valid Allocation and access--\n");

    int *data = SAFE_MALLOC(int, 8);
    for (int i = 0; i < 8; i++)
    {
        CHECK_WRITE(&data[i], sizeof(int));
        data[i] = i * 10;
    }
    for (int i = 0; i < 8; i++)
    {
        CHECK_READ(&data[i], sizeof(int));
        printf("data[%d]= %d\n", i, data[i]);
    }

    SAFE_FREE(data);
    fprintf(stderr, "ex.1 complete-- \n");
}

static void example_overflow()
{
    fprintf(stderr, "\n--ex2. Heap buffer overflow--\n");

    char *buf = SAFE_MALLOC(char, 10);
    for (int i = 0; i <= 10; i++)
    {
        CHECK_WRITE(&buf[i], sizeof(char));
        buf[i] = static_cast<char>(i);
    }

    SAFE_FREE(buf);
}

static void example_use_after_free()
{
    fprintf(stderr, "\n ex3. use after free");
    int *p = SAFE_MALLOC(int, 4);
    p[0] = 42;
    SAFE_FREE(p);
    CHECK_READ(p, sizeof(int));
    volatile int x = p[0];
    (void)x;
}

static void example_custom_poison()
{
    fprintf(stderr, "\n ex4. Custom poison/ unpoison");

    static char pool[256];                                // pool allocator which manages its own memeory
    asan_poison(pool, 16, ASAN_POISON_HEAP_LEFT_REDZONE); // amrkin first 16bytes as guardzone
    asan_unpoison(pool + 16, 32);                         //[16, 48] as usable

    CHECK_WRITE(pool + 16, sizeof(int));
    fprintf(stderr, "  pool[16] write: OK\n");
    CHECK_WRITE(pool, sizeof(int)); //triggers errror report

    asan_unpoison(pool, sizeof(pool));
    fprintf(stderr, "ex 4. complete \n");
}

int main() {
    asan_init();

    example_valid();
    example_overflow();
    example_use_after_free();
    example_custom_poison();

    asan_report_summary();
    asan_shutdown();

    return 0;
}