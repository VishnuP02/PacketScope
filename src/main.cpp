#include <pcap.h>
#include <iostream>

void packetHandler(unsigned char* userData, const struct pcap_pkthdr* packetHeader, const unsigned char* packetData) {
    static int packetCount = 0;
    packetCount++;

    std::cout << "Packet #" << packetCount
              << " | Length: " << packetHeader->len
              << " bytes"
              << std::endl;
}

int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    const char* device = "en0";

    pcap_t* handle = pcap_open_live(
        device,
        BUFSIZ,
        1,
        1000,
        errorBuffer
    );

    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errorBuffer << std::endl;
        return 1;
    }

    std::cout << "Capturing packets on interface: " << device << std::endl;
    std::cout << "Press Ctrl+C to stop.\n";

    pcap_loop(handle, 10, packetHandler, nullptr);

    pcap_close(handle);

    std::cout << "Capture complete." << std::endl;

    return 0;
}