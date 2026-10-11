#include <iostream>
#include <cstdio>
#include <string>
int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::string mode(argv[1]);
    const std::string input(argv[2]);
    if (mode == "copy") std::cout << "Copied: " << input << '\n';
    else if (mode == "format") std::printf("%s", input.c_str());
    else if (mode == "command") std::cout << input << '\n';
    else return 2;
    return 0;
}
