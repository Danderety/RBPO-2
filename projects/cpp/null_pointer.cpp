// Assignment section 3.5: CPP-04 CWE-476, intentionally unsafe example.
#include <iostream>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif

void process_data(int* data) {
    *data = 42; // CPP-04 CWE-476: caller may pass nullptr.
}

int main(int argc, char** argv) {
#ifdef _WIN32
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
#endif
    if (argc != 2) return 2;
    const std::string mode = argv[1];
    if (mode != "null" && mode != "valid") return 2;
    int value = 0;
    process_data(mode == "null" ? nullptr : &value);
    std::cout << value << '\n';
    return 0;
}
