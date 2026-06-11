#include <pcap.h>
#include <iostream>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <fstream>
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
std::map<std::string, int> connectionCounts;
std::ofstream logFile;
std::string packetFilter = "all";

void logPacket(const std::string& message) {
    if (logFile.is_open()) {
        logFile << message << std::endl;
    }
}

void trackConnection(const std::string& sourceIp, const std::string& destinationIp) {
    std::string connection = sourceIp + " -> " + destinationIp;
    connectionCounts[connection]++;
}

bool shouldDisplayType(const std::string& type) {
    return packetFilter == "all" || packetFilter == type;
}

bool shouldDisplayProtocol(const std::string& protocol) {
    return packetFilter == "all" || packetFilter == protocol;
}

void processOutput(const std::string& output) {
    std::cout << output << std::endl;
    logPacket(output);
}

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

        std::string sourceIp = inet_ntoa(ipHeader->ip_src);
        std::string destinationIp = inet_ntoa(ipHeader->ip_dst);
        std::string protocolName;

        trackConnection(sourceIp, destinationIp);

        switch (ipHeader->ip_p) {
            case IPPROTO_TCP:
                stats.tcpPackets++;
                protocolName = "tcp";
                break;
            case IPPROTO_UDP:
                stats.udpPackets++;
                protocolName = "udp";
                break;
            case IPPROTO_ICMP:
                stats.icmpPackets++;
                protocolName = "icmp";
                break;
            default:
                stats.otherPackets++;
                protocolName = "other";
                break;
        }

        if (!shouldDisplayType("ipv4") && !shouldDisplayProtocol(protocolName)) {
            return;
        }

        std::string output =
            "Packet #" + std::to_string(stats.totalPackets) +
            " | Length: " + std::to_string(packetHeader->len) + " bytes" +
            " | Type: IPv4" +
            " | Source IP: " + sourceIp +
            " | Destination IP: " + destinationIp +
            " | Protocol: " + protocolName;

        processOutput(output);
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

        std::string sourceIp = src;
        std::string destinationIp = dst;
        std::string protocolName;

        trackConnection(sourceIp, destinationIp);

        switch (ip6Header->ip6_nxt) {
            case IPPROTO_TCP:
                stats.tcpPackets++;
                protocolName = "tcp";
                break;
            case IPPROTO_UDP:
                stats.udpPackets++;
                protocolName = "udp";
                break;
            case IPPROTO_ICMPV6:
                stats.icmpv6Packets++;
                protocolName = "icmpv6";
                break;
            default:
                stats.otherPackets++;
                protocolName = "other";
                break;
        }

        if (!shouldDisplayType("ipv6") && !shouldDisplayProtocol(protocolName)) {
            return;
        }

        std::string output =
            "Packet #" + std::to_string(stats.totalPackets) +
            " | Length: " + std::to_string(packetHeader->len) + " bytes" +
            " | Type: IPv6" +
            " | Source IP: " + sourceIp +
            " | Destination IP: " + destinationIp +
            " | Protocol: " + protocolName;

        processOutput(output);
    }
    else {
        stats.otherPackets++;

        if (!shouldDisplayProtocol("other")) {
            return;
        }

        std::string output =
            "Packet #" + std::to_string(stats.totalPackets) +
            " | Length: " + std::to_string(packetHeader->len) +
            " bytes | Non-IP packet";

        processOutput(output);
    }
}

void printTrafficSummary() {
    double averagePacketSize = 0.0;

    if (stats.totalPackets > 0) {
        averagePacketSize =
            static_cast<double>(stats.totalBytes) / stats.totalPackets;
    }

    std::cout << "\n========== Traffic Summary ==========" << std::endl;
    std::cout << "Filter: " << packetFilter << std::endl;
    std::cout << "Total Packets Captured: " << stats.totalPackets << std::endl;
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

void printTopConnections() {
    std::vector<std::pair<std::string, int>> connections(
        connectionCounts.begin(),
        connectionCounts.end()
    );

    std::sort(
        connections.begin(),
        connections.end(),
        [](const auto& a, const auto& b) {
            return a.second > b.second;
        }
    );

    std::cout << "\n========== Top Connections ==========" << std::endl;

    if (connections.empty()) {
        std::cout << "No IP connections captured." << std::endl;
    }
    else {
        int limit = std::min(5, static_cast<int>(connections.size()));

        for (int i = 0; i < limit; i++) {
            std::cout << i + 1 << ". "
                      << connections[i].first
                      << " | Packets: "
                      << connections[i].second
                      << std::endl;
        }
    }

    std::cout << "=====================================" << std::endl;
}

void printUsage() {
    std::cout << "Usage: sudo ./packetscope [filter]" << std::endl;
    std::cout << "Available filters: all, tcp, udp, icmp, icmpv6, ipv4, ipv6, other" << std::endl;
}

int main(int argc, char* argv[]) {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    const char* device = "en0";

    if (argc > 1) {
        packetFilter = argv[1];
    }

    if (packetFilter != "all" &&
        packetFilter != "tcp" &&
        packetFilter != "udp" &&
        packetFilter != "icmp" &&
        packetFilter != "icmpv6" &&
        packetFilter != "ipv4" &&
        packetFilter != "ipv6" &&
        packetFilter != "other") {
        printUsage();
        return 1;
    }

    logFile.open("capture.log");

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
    std::cout << "Active filter: " << packetFilter << std::endl;
    std::cout << "Logging packets to capture.log" << std::endl;
    std::cout << "Capturing 100 packets...\n" << std::endl;

    pcap_loop(handle, 100, packetHandler, nullptr);

    pcap_close(handle);

    std::cout << "\nCapture complete." << std::endl;

    printTrafficSummary();
    printTopConnections();

    if (logFile.is_open()) {
        logFile.close();
    }

    return 0;
}