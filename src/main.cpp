#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

struct TrafficStats {
    int totalPackets = 0;
    int ipv4Packets = 0;
    int ipv6Packets = 0;
    int tcpPackets = 0;
    int udpPackets = 0;
    int icmpPackets = 0;
    int icmpv6Packets = 0;
    int otherPackets = 0;
    long totalBytes = 0;
};

TrafficStats stats;

void packetHandler(unsigned char* userData,
                   const struct pcap_pkthdr* packetHeader,
                   const unsigned char* packetData) {
    stats.totalPackets++;
    stats.totalBytes += packetHeader->len;

    if (packetHeader->len < sizeof(struct ether_header) + sizeof(struct ip)) {
        stats.otherPackets++;
        return;
    }

    const struct ether_header* ethernetHeader =
        reinterpret_cast<const struct ether_header*>(packetData);

    uint16_t etherType = ntohs(ethernetHeader->ether_type);

    if (etherType == ETHERTYPE_IP) {
        stats.ipv4Packets++;

        const struct ip* ipHeader =
            reinterpret_cast<const struct ip*>(
                packetData + sizeof(struct ether_header));

        std::cout << "Packet #" << stats.totalPackets
                  << " | Length: " << packetHeader->len << " bytes"
                  << " | Type: IPv4"
                  << " | Source IP: " << inet_ntoa(ipHeader->ip_src)
                  << " | Destination IP: " << inet_ntoa(ipHeader->ip_dst)
                  << " | Protocol: ";

        switch (ipHeader->ip_p) {
            case IPPROTO_TCP:
                stats.tcpPackets++;
                std::cout << "TCP";
                break;
            case IPPROTO_UDP:
                stats.udpPackets++;
                std::cout << "UDP";
                break;
            case IPPROTO_ICMP:
                stats.icmpPackets++;
                std::cout << "ICMP";
                break;
            default:
                stats.otherPackets++;
                std::cout << "Other";
                break;
        }

        std::cout << std::endl;
    }
    else if (etherType == ETHERTYPE_IPV6) {
        stats.ipv6Packets++;

        const struct ip6_hdr* ip6Header =
            reinterpret_cast<const struct ip6_hdr*>(
                packetData + sizeof(struct ether_header));

        char src[INET6_ADDRSTRLEN];
        char dst[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &(ip6Header->ip6_src), src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6Header->ip6_dst), dst, INET6_ADDRSTRLEN);

        std::cout << "Packet #" << stats.totalPackets
                  << " | Length: " << packetHeader->len << " bytes"
                  << " | Type: IPv6"
                  << " | Source IP: " << src
                  << " | Destination IP: " << dst
                  << " | Protocol: ";

        switch (ip6Header->ip6_nxt) {
            case IPPROTO_TCP:
                stats.tcpPackets++;
                std::cout << "TCP";
                break;
            case IPPROTO_UDP:
                stats.udpPackets++;
                std::cout << "UDP";
                break;
            case IPPROTO_ICMPV6:
                stats.icmpv6Packets++;
                std::cout << "ICMPv6";
                break;
            default:
                stats.otherPackets++;
                std::cout << "Other";
                break;
        }

        std::cout << std::endl;
    }
    else {
        stats.otherPackets++;

        std::cout << "Packet #" << stats.totalPackets
                  << " | Length: " << packetHeader->len
                  << " bytes | Non-IP packet"
                  << std::endl;
    }
}

void printTrafficSummary() {
    double averagePacketSize = 0.0;

    if (stats.totalPackets > 0) {
        averagePacketSize =
            static_cast<double>(stats.totalBytes) / stats.totalPackets;
    }

    std::cout << "\n========== Traffic Summary ==========" << std::endl;
    std::cout << "Total Packets: " << stats.totalPackets << std::endl;
    std::cout << "IPv4 Packets: " << stats.ipv4Packets << std::endl;
    std::cout << "IPv6 Packets: " << stats.ipv6Packets << std::endl;
    std::cout << "TCP Packets: " << stats.tcpPackets << std::endl;
    std::cout << "UDP Packets: " << stats.udpPackets << std::endl;
    std::cout << "ICMP Packets: " << stats.icmpPackets << std::endl;
    std::cout << "ICMPv6 Packets: " << stats.icmpv6Packets << std::endl;
    std::cout << "Other Packets: " << stats.otherPackets << std::endl;
    std::cout << "Total Bytes: " << stats.totalBytes << std::endl;
    std::cout << "Average Packet Size: " << averagePacketSize << " bytes" << std::endl;
    std::cout << "=====================================" << std::endl;
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
    std::cout << "Capturing packets on interface: " << device << std::endl;
    std::cout << "Capturing 50 packets...\n" << std::endl;

    pcap_loop(handle, 50, packetHandler, nullptr);

    pcap_close(handle);

    std::cout << "\nCapture complete." << std::endl;

    printTrafficSummary();

    return 0;
}