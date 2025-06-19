// Main application to launch Spotify with LD_PRELOAD
#include <cstdlib>
#include <unistd.h>
#include <iostream>

int main() {
    // Set LD_PRELOAD to load the shared library
    if (setenv("LD_PRELOAD", "./libspotifyhook.so", 1) != 0) {
        std::cerr << "Failed to set LD_PRELOAD" << std::endl;
        return 1;
    }

    // Launch Spotify (assumes Spotify is installed at /usr/bin/spotify)
    execl("/usr/bin/spotify", "spotify", nullptr);

    // If execl fails
    std::cerr << "Failed to launch Spotify" << std::endl;
    return 1;
}