#include <iostream>

int main()
{
    std::cout << "Testing heap buffer overflow...\n";

    int *arr = new int[10];
    std::cout << "Attempting to access arr[15] overflow..\n";
    arr[15] = 42;
    delete[] arr;

    return 0;
}