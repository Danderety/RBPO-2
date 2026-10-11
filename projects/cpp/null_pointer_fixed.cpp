// Targeted fix for CPP-04; invalid input is handled explicitly.
#include <iostream>
#include <string>

bool process_data(int* data) {
    if (data == nullptr) return false;
    *data = 42;
    return true;
}

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    const std::string mode = argv[1];
    if (mode != "null" && mode != "valid") return 2;
    int value = 0;
    if (!process_data(mode == "null" ? nullptr : &value)) {
        std::cout << "null rejected\n";
        return 0;
    }
    std::cout << value << '\n';
    return 0;
}
