#include "packetscope/display.hpp"

#include <cstdio>
#include <sstream>

namespace ps {

bool DisplayFilter::parse(const std::string& name, DisplayFilter& out) {
    static const char* kNames[] = {"all", "tcp", "udp", "icmp", "icmpv6", "ipv4", "ipv6", "other"};
    for (const char* n : kNames) {
        if (name == n) {
            out = DisplayFilter(name);
            return true;
        }
    }
    return false;
}

bool DisplayFilter::matches(const ParsedPacket& p) const {
    if (name_ == "all") {
        return true;
    }
    if (p.status != Status::Ok) {
        return name_ == "other";
    }
    if (name_ == "ipv4") {
        return p.ip_version == 4;
    }
    if (name_ == "ipv6") {
        return p.ip_version == 6;
    }
    return name_ == protocol_name(p.protocol);
}

static std::string endpoint(const std::string& ip, bool has_port, uint16_t port, int ip_version) {
    if (!has_port) {
        return ip;
    }
    return ip_version == 6 ? "[" + ip + "]:" + std::to_string(port) : ip + ":" + std::to_string(port);
}

std::string format_packet_line(uint64_t number, uint32_t wire_len, const ParsedPacket& p) {
    std::ostringstream out;
    out << "Packet #" << number << " | Length: " << wire_len << " bytes";
    switch (p.status) {
        case Status::Truncated:
            out << " | Truncated capture";
            break;
        case Status::Malformed:
            out << " | Malformed header";
            break;
        case Status::NonIp:
            out << " | Non-IP packet (ethertype 0x" << std::hex << p.ether_type << ")";
            break;
        case Status::Ok:
            out << " | Type: IPv" << p.ip_version << " | Source: "
                << endpoint(p.src, p.has_ports, p.src_port, p.ip_version) << " | Destination: "
                << endpoint(p.dst, p.has_ports, p.dst_port, p.ip_version)
                << " | Protocol: " << protocol_name(p.protocol);
            if (p.protocol == Protocol::Tcp && p.has_ports) {
                out << " [" << format_tcp_flags(p.tcp_flags) << "]";
            }
            if (p.is_fragment) {
                out << " (fragment)";
            }
            break;
    }
    return out.str();
}

std::string format_summary(const TrafficAnalyzer& analyzer, const std::string& filter_name) {
    const TrafficStats& s = analyzer.stats();
    char avg[32];
    std::snprintf(avg, sizeof avg, "%.1f", s.average_size());
    std::ostringstream out;
    out << "\n========== Traffic Summary ==========\n"
        << "Display filter: " << filter_name << "\n"
        << "Total Packets: " << s.total << "\n"
        << "IPv4 Packets: " << s.ipv4 << "\n"
        << "IPv6 Packets: " << s.ipv6 << "\n"
        << "TCP Packets: " << s.tcp << "\n"
        << "UDP Packets: " << s.udp << "\n"
        << "ICMP Packets: " << s.icmp << "\n"
        << "ICMPv6 Packets: " << s.icmpv6 << "\n"
        << "Other IP Packets: " << s.other << "\n"
        << "Non-IP Packets: " << s.non_ip << "\n"
        << "Truncated Packets: " << s.truncated << "\n"
        << "Malformed Packets: " << s.malformed << "\n"
        << "Total Bytes: " << s.bytes << "\n"
        << "Average Packet Size: " << avg << " bytes\n"
        << "=====================================\n";
    return out.str();
}

std::string format_top_connections(const TrafficAnalyzer& analyzer, std::size_t n) {
    const auto top = analyzer.top_connections(n);
    std::ostringstream out;
    out << "\n========== Top Connections ==========\n";
    if (top.empty()) {
        out << "No IP connections captured.\n";
    }
    for (std::size_t i = 0; i < top.size(); ++i) {
        out << (i + 1) << ". " << top[i].first << " | Packets: " << top[i].second << "\n";
    }
    out << "=====================================\n";
    return out.str();
}

std::string format_top_ports(const TrafficAnalyzer& analyzer, std::size_t n) {
    const auto top = analyzer.top_ports(n);
    std::ostringstream out;
    out << "\n========== Top Destination Ports ==========\n";
    if (top.empty()) {
        out << "No TCP/UDP traffic captured.\n";
    }
    for (std::size_t i = 0; i < top.size(); ++i) {
        out << (i + 1) << ". port " << top[i].first << " | Packets: " << top[i].second << "\n";
    }
    out << "===========================================\n";
    return out.str();
}

std::string format_scan_alerts(const TrafficAnalyzer& analyzer) {
    const auto scanners = analyzer.suspected_scanners();
    if (scanners.empty()) {
        return "";
    }
    std::ostringstream out;
    out << "\n========== Possible Port Scans ==========\n";
    for (const std::string& s : scanners) {
        out << "ALERT: " << s << " sent SYN-only packets to many distinct ports\n";
    }
    out << "=========================================\n";
    return out.str();
}

}  // namespace ps
