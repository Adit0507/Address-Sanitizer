#include <iostream>

int main(){
    std:: cout << "Testing use after free";

    int *ptr= new int(42);
    std:: cout << "Allocated and initialized: "<< *ptr<< "\n";

    return 0;
}