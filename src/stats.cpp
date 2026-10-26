#include "packetscope/stats.hpp"

#include <algorithm>

namespace ps {

TrafficAnalyzer::TrafficAnalyzer(std::size_t scan_threshold) : scan_threshold_(scan_threshold) {}

void TrafficAnalyzer::record(const ParsedPacket& p, uint32_t wire_len) {
    ++stats_.total;
    stats_.bytes += wire_len;

    switch (p.status) {
        case Status::Truncated:
            ++stats_.truncated;
            return;
        case Status::Malformed:
            ++stats_.malformed;
            return;
        case Status::NonIp:
            ++stats_.non_ip;
            return;
        case Status::Ok:
            break;
    }

    if (p.ip_version == 4) {
        ++stats_.ipv4;
    } else {
        ++stats_.ipv6;
    }
    switch (p.protocol) {
        case Protocol::Tcp:
            ++stats_.tcp;
            break;
        case Protocol::Udp:
            ++stats_.udp;
            break;
        case Protocol::Icmp:
            ++stats_.icmp;
            break;
        case Protocol::Icmpv6:
            ++stats_.icmpv6;
            break;
        default:
            ++stats_.other;
            break;
    }

    ++connections_[p.src + " -> " + p.dst];
    if (p.has_ports) {
        ++ports_[p.dst_port];
    }

    const bool syn_only = p.protocol == Protocol::Tcp && p.has_ports && (p.tcp_flags & kTcpSyn) &&
                          !(p.tcp_flags & kTcpAck);
    if (syn_only && scan_threshold_ > 0) {  // a threshold of 0 disables scan detection
        auto& targets = syn_targets_[p.src];
        if (targets.size() < scan_threshold_) {  // stop storing once the threshold is reached
            targets.insert(p.dst_port);
        }
    }
}

std::vector<std::pair<std::string, uint64_t>> TrafficAnalyzer::top_connections(std::size_t n) const {
    std::vector<std::pair<std::string, uint64_t>> v(connections_.begin(), connections_.end());
    std::stable_sort(v.begin(), v.end(), [](const std::pair<std::string, uint64_t>& a, const std::pair<std::string, uint64_t>& b) {
        return a.second > b.second;
    });
    if (v.size() > n) {
        v.resize(n);
    }
    return v;
}

std::vector<std::pair<uint16_t, uint64_t>> TrafficAnalyzer::top_ports(std::size_t n) const {
    std::vector<std::pair<uint16_t, uint64_t>> v(ports_.begin(), ports_.end());
    std::stable_sort(v.begin(), v.end(), [](const std::pair<uint16_t, uint64_t>& a, const std::pair<uint16_t, uint64_t>& b) {
        return a.second > b.second;
    });
    if (v.size() > n) {
        v.resize(n);
    }
    return v;
}

std::vector<std::string> TrafficAnalyzer::suspected_scanners() const {
    std::vector<std::string> out;
    if (scan_threshold_ == 0) {
        return out;
    }
    for (const auto& kv : syn_targets_) {
        if (kv.second.size() >= scan_threshold_) {
            out.push_back(kv.first);
        }
    }
    return out;
}

}  // namespace ps
