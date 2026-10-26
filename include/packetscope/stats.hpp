#ifndef PACKETSCOPE_STATS_HPP
#define PACKETSCOPE_STATS_HPP

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "packetscope/parser.hpp"

namespace ps {

struct TrafficStats {
    uint64_t total = 0;
    uint64_t bytes = 0;
    uint64_t ipv4 = 0;
    uint64_t ipv6 = 0;
    uint64_t tcp = 0;
    uint64_t udp = 0;
    uint64_t icmp = 0;
    uint64_t icmpv6 = 0;
    uint64_t other = 0;      // IP packets with another transport protocol
    uint64_t non_ip = 0;     // e.g. ARP
    uint64_t truncated = 0;  // capture ended inside a header
    uint64_t malformed = 0;  // impossible header values
    double average_size() const { return total == 0 ? 0.0 : static_cast<double>(bytes) / static_cast<double>(total); }
};

class TrafficAnalyzer {
public:
    // A source is reported as a suspected scanner once it has sent TCP SYN-only packets
    // to at least scan_threshold distinct destination ports. A threshold of 0 disables detection.
    explicit TrafficAnalyzer(std::size_t scan_threshold = 20);

    void record(const ParsedPacket& packet, uint32_t wire_len);

    const TrafficStats& stats() const { return stats_; }
    // Highest count first; ties broken alphabetically so output is deterministic.
    std::vector<std::pair<std::string, uint64_t>> top_connections(std::size_t n) const;
    std::vector<std::pair<uint16_t, uint64_t>> top_ports(std::size_t n) const;
    std::vector<std::string> suspected_scanners() const;

private:
    std::size_t scan_threshold_;
    TrafficStats stats_;
    std::map<std::string, uint64_t> connections_;
    std::map<uint16_t, uint64_t> ports_;
    std::map<std::string, std::set<uint16_t>> syn_targets_;
};

}  // namespace ps

#endif
