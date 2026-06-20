#include "asan.h"
#include <cstdio>

int main() {
    asan_init();

    int *p= SAFE_MALLOC(int, 0);
    p[0] = 1;

    fprintf(stderr, "[test] First free...");
    SAFE_FREE(p);

    fprintf(stderr, "[test] second free(double free)...\n");
    asan_free(p);  //double free 

    asan_shutdown();
    return 0;
}