#include <pcap.h>
#include <iostream>

int main() {
    char errorBuffer[PCAP_ERRBUF_SIZE];

    pcap_if_t* devices;
    if (pcap_findalldevs(&devices, errorBuffer) == -1) {
        std::cerr << "Error finding devices: " << errorBuffer << std::endl;
        return 1;
    }

    std::cout << "Available network interfaces:\n";

    int count = 0;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        std::cout << ++count << ". " << device->name;

        if (device->description) {
            std::cout << " - " << device->description;
        }

        std::cout << std::endl;
    }

    pcap_freealldevs(devices);

    return 0;
}