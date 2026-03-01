#include <iostream>
#include <cstring>
#include "../src/runtime/asan_stack.h"
#include "../src/runtime/asan_interface.h"

void vulnerable_function() {
    char buffer[10];

    char left_redzone[0];
    char right_redzone[0];
    __asan_poison_memory_region(left_redzone, 8);
    __asan_poison_memory_region(right_redzone, 8);

    std:: cout << "Attempting stack overflow..\n";
    for(int i= 0; i< 20; i++){ //will trigger an error
        buffer[i]= 'A'; //overflow
    }

    __asan_unpoison_memory_region(left_redzone, 8);
    __asan_unpoison_memory_region(right_redzone, 8);
}

int main(){
    std::cout << "Testing stack buffer overflow...\n";
    vulnerable_function();
    return 0;
}