#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

void packetHandler(unsigned char* userData,
                   const struct pcap_pkthdr* packetHeader,
                   const unsigned char* packetData) {
    static int packetCount = 0;
    packetCount++;

    if (packetHeader->len < sizeof(struct ether_header) + sizeof(struct ip)) {
        return;
    }

    const struct ether_header* ethernetHeader =
        reinterpret_cast<const struct ether_header*>(packetData);

    uint16_t etherType = ntohs(ethernetHeader->ether_type);

    if (etherType == ETHERTYPE_IP) {
        const struct ip* ipHeader =
            reinterpret_cast<const struct ip*>(
                packetData + sizeof(struct ether_header));

        std::cout << "Packet #" << packetCount
                  << " | Length: " << packetHeader->len << " bytes"
                  << " | Type: IPv4"
                  << " | Source IP: " << inet_ntoa(ipHeader->ip_src)
                  << " | Destination IP: " << inet_ntoa(ipHeader->ip_dst)
                  << " | Protocol: ";

        switch (ipHeader->ip_p) {
            case IPPROTO_TCP:
                std::cout << "TCP";
                break;
            case IPPROTO_UDP:
                std::cout << "UDP";
                break;
            case IPPROTO_ICMP:
                std::cout << "ICMP";
                break;
            default:
                std::cout << "Other";
                break;
        }

        std::cout << std::endl;
    }
    else if (etherType == ETHERTYPE_IPV6) {
        const struct ip6_hdr* ip6Header =
            reinterpret_cast<const struct ip6_hdr*>(
                packetData + sizeof(struct ether_header));

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6,
                  &(ip6Header->ip6_src),
                  src,
                  INET6_ADDRSTRLEN);

        inet_ntop(AF_INET6,
                  &(ip6Header->ip6_dst),
                  dst,
                  INET6_ADDRSTRLEN);

        std::cout << "Packet #" << packetCount
                  << " | Length: " << packetHeader->len << " bytes"
                  << " | Type: IPv6"
                  << " | Source IP: " << src
                  << " | Destination IP: " << dst
                  << " | Protocol: ";

        switch (ip6Header->ip6_nxt) {
            case IPPROTO_TCP:
                std::cout << "TCP";
                break;
            case IPPROTO_UDP:
                std::cout << "UDP";
                break;
            case IPPROTO_ICMPV6:
                std::cout << "ICMPv6";
                break;
            default:
                std::cout << "Other";
                break;
        }

        std::cout << std::endl;
    }
    else {
        std::cout << "Packet #" << packetCount
                  << " | Length: " << packetHeader->len
                  << " bytes | Non-IP packet"
                  << std::endl;
    }
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
        std::cerr << "Could not open device "
                  << device
                  << ": "
                  << errorBuffer
                  << std::endl;
        return 1;
    }

    std::cout << "PacketScope - Live Network Traffic Analyzer" << std::endl;
    std::cout << "Capturing packets on interface: "
              << device
              << std::endl;
    std::cout << "Capturing 30 packets...\n" << std::endl;

    pcap_loop(handle, 30, packetHandler, nullptr);

    pcap_close(handle);

    std::cout << "\nCapture complete." << std::endl;

    return 0;
}