#ifndef PACKETSCOPE_PARSER_HPP
#define PACKETSCOPE_PARSER_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace ps {

enum class Status {
    Ok,         // headers parsed
    NonIp,      // valid Ethernet frame carrying something other than IPv4/IPv6 (e.g. ARP)
    Truncated,  // the capture ended before a header was complete
    Malformed   // a header field has an impossible value
};

enum class Protocol { None, Tcp, Udp, Icmp, Icmpv6, Other };

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpPsh = 0x08;
constexpr uint8_t kTcpAck = 0x10;
constexpr uint8_t kTcpUrg = 0x20;

struct ParsedPacket {
    Status status = Status::Truncated;
    uint16_t ether_type = 0;
    bool vlan = false;
    int ip_version = 0;  // 4, 6, or 0 when no IP header was parsed
    std::string src;
    std::string dst;
    Protocol protocol = Protocol::None;
    uint8_t ip_protocol = 0;  // raw IPv4 protocol / IPv6 next-header value
    uint8_t ttl = 0;          // IPv4 TTL or IPv6 hop limit
    bool is_fragment = false;
    bool has_ports = false;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0;
};

// Parses an Ethernet frame. Every read is bounds-checked against len, so any byte sequence,
// however short or corrupt, is safe to pass in. Checksums are not verified.
ParsedPacket parse_ethernet(const uint8_t* data, size_t len);

const char* protocol_name(Protocol p);
std::string format_tcp_flags(uint8_t flags);

}  // namespace ps

#endif
