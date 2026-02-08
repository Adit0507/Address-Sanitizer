#include <iostream>

int main()
{
    std::cout << "Testing use after free";

    int *ptr = new int(42);
    std::cout << "Allocated and initialized: " << *ptr << "\n";

    delete ptr;
    std::cout << "Freed the pointer\n";

    std::cout << "Attempting to use freed memory..\n";
    *ptr = 100;
    return 0;
}