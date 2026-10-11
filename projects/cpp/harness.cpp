// Calls original functions independently, avoiding cascade crashes.
#define LAB_HARNESS
#include "vulnerable.cpp"
#include <string>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::string mode(argv[1]);
    if (mode == "copy") vulnerable_copy(argv[2]);
    else if (mode == "format") vulnerable_printf(argv[2]);
    else if (mode == "command") vulnerable_system(argv[2]);
    else return 2;
}
