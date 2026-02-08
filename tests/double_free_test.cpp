#include <iostream>

int main()
{
    std::cout << "Testing double-free...";

    int *ptr = new int(42);
    std::cout << "Allocated: " << *ptr << "\n";
    delete ptr;

    std:: cout << "First free\n";

    std:: cout <<"Attempting double free...\n";
    delete ptr; //double fre
    return 0;
}