/*
    Shellcode Loader
    Archive of Reversing.ID

    Executing shellcode as new thread.

Compile:
    $ g++ code.cpp

Technique:
    - allocation: mmap
    - writing:    memcpy
    - permission: mprotect
    - execution:
*/

#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>

void execute_shellcode(const uint8_t* payload, size_t payload_len) {
    // Allocate memory buffer for payload as READ-WRITE (no executable)
    void *runtime = mmap(0, payload_len, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (runtime == MAP_FAILED) {
        perror("mmap failed");
        return;
    }

    // Copy payload to the buffer
    memcpy(runtime, payload, payload_len);

    // Make buffer executable (R-X)
    int retval = mprotect(runtime, payload_len, PROT_READ | PROT_EXEC);
    if (retval == 0) {
        // Create pointer to function and assign with address of shellcode
        int (*func)() = (int (*)())runtime;

        // Execute shellcode
        func();
    } else {
        perror("mprotect failed");
    }

    // Deallocate memory map
    munmap(runtime, payload_len);
}

std::vector<uint8_t> parse_shellcode(int argc, char* argv[]) {
    std::vector<uint8_t> shellcode;
    
    for (int i = 1; i < argc; ++i) { // Start from 1 to skip the program name
        std::string hex_value = argv[i];
        // Convert hex string to integer
        uint8_t byte = static_cast<uint8_t>(strtol(hex_value.c_str(), nullptr, 16));
        shellcode.push_back(byte);
    }
    
    return shellcode;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <shellcode_in_hex>" << std::endl;
        return 1;
    }

    // Parse shellcode from command-line arguments
    std::vector<uint8_t> payload = parse_shellcode(argc, argv);
    size_t payload_len = payload.size();

    // Call the function to execute shellcode
    execute_shellcode(payload.data(), payload_len);

    return 0;
}
