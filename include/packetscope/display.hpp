#ifndef PACKETSCOPE_DISPLAY_HPP
#define PACKETSCOPE_DISPLAY_HPP

#include <cstdint>
#include <utility>
#include <string>

#include "packetscope/parser.hpp"
#include "packetscope/stats.hpp"

namespace ps {

// Chooses which packets are printed. Statistics always count every packet.
// Accepted names: all, tcp, udp, icmp, icmpv6, ipv4, ipv6, other.
// "other" also matches non-IP, truncated, and malformed packets.
class DisplayFilter {
public:
    DisplayFilter() : name_("all") {}
    // Returns false (leaving out unchanged) when the name is not recognized.
    static bool parse(const std::string& name, DisplayFilter& out);
    bool matches(const ParsedPacket& packet) const;
    const std::string& name() const { return name_; }

private:
    explicit DisplayFilter(const std::string& name) : name_(name) {}
    std::string name_;
};

std::string format_packet_line(uint64_t number, uint32_t wire_len, const ParsedPacket& packet);
std::string format_summary(const TrafficAnalyzer& analyzer, const std::string& filter_name);
std::string format_top_connections(const TrafficAnalyzer& analyzer, std::size_t n);
std::string format_top_ports(const TrafficAnalyzer& analyzer, std::size_t n);
std::string format_scan_alerts(const TrafficAnalyzer& analyzer);

}  // namespace ps

#endif
