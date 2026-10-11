// Source: practical assignment 2; defects retained intentionally.
#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>
using namespace std;

void vulnerable_copy(char* input) {
    char buffer[10];
    strcpy(buffer, input); // CPP-01 CWE-120, stack variant CWE-121
    cout << "Copied: " << buffer << endl;
}
void vulnerable_printf(char* input) {
    printf(input); // CPP-02 CWE-134
}
void vulnerable_system(char* input) {
    char command[100];
    sprintf(command, "echo %s", input); // Additional unbounded write
    system(command); // CPP-03 CWE-78
}
#ifndef LAB_HARNESS
int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    vulnerable_copy(argv[1]);
    vulnerable_printf(argv[1]);
    vulnerable_system(argv[1]);
    return 0;
}
#endif
