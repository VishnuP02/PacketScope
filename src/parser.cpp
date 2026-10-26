#include "packetscope/parser.hpp"

#include <algorithm>
#include <cstdio>

namespace ps {

namespace {

constexpr uint16_t kEtherIpv4 = 0x0800;
constexpr uint16_t kEtherIpv6 = 0x86DD;
constexpr uint16_t kEtherVlan = 0x8100;
constexpr uint16_t kEtherQinQ = 0x88A8;

constexpr size_t kEthernetHeader = 14;
constexpr size_t kVlanTag = 4;
constexpr size_t kIpv4MinHeader = 20;
constexpr size_t kIpv6Header = 40;
constexpr int kMaxExtensionHeaders = 8;

uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

std::string format_ipv4(const uint8_t* a) {
    return std::to_string(a[0]) + "." + std::to_string(a[1]) + "." + std::to_string(a[2]) + "." +
           std::to_string(a[3]);
}

// RFC 5952 style: lowercase hex, the longest run of two or more zero groups becomes "::".
std::string format_ipv6(const uint8_t* a) {
    uint16_t g[8];
    for (int i = 0; i < 8; ++i) {
        g[i] = be16(a + 2 * i);
    }
    int best_start = -1;
    int best_len = 0;
    for (int i = 0; i < 8;) {
        if (g[i] == 0) {
            int j = i;
            while (j < 8 && g[j] == 0) {
                ++j;
            }
            if (j - i > best_len) {
                best_len = j - i;
                best_start = i;
            }
            i = j;
        } else {
            ++i;
        }
    }
    if (best_len < 2) {
        best_start = -1;
    }
    std::string out;
    for (int i = 0; i < 8;) {
        if (i == best_start) {
            out += "::";
            i += best_len;
            continue;
        }
        if (!out.empty() && out.back() != ':') {
            out += ':';
        }
        char buf[8];
        std::snprintf(buf, sizeof buf, "%x", static_cast<unsigned>(g[i]));
        out += buf;
        ++i;
    }
    return out;
}

Protocol classify(uint8_t proto, bool ipv6) {
    switch (proto) {
        case 6:
            return Protocol::Tcp;
        case 17:
            return Protocol::Udp;
        case 1:
            return ipv6 ? Protocol::Other : Protocol::Icmp;
        case 58:
            return ipv6 ? Protocol::Icmpv6 : Protocol::Other;
        default:
            return Protocol::Other;
    }
}

// Parses the transport header. avail is the number of bytes the IP layer says belong to it
// and that were actually captured.
void parse_transport(ParsedPacket& r, const uint8_t* p, size_t avail) {
    switch (r.protocol) {
        case Protocol::Tcp: {
            if (avail < 20) {
                r.status = Status::Truncated;
                return;
            }
            const size_t data_offset = static_cast<size_t>(p[12] >> 4) * 4;
            if (data_offset < 20) {
                r.status = Status::Malformed;
                return;
            }
            if (avail < data_offset) {
                r.status = Status::Truncated;
                return;
            }
            r.src_port = be16(p);
            r.dst_port = be16(p + 2);
            r.tcp_flags = p[13];
            r.has_ports = true;
            break;
        }
        case Protocol::Udp: {
            if (avail < 8) {
                r.status = Status::Truncated;
                return;
            }
            if (be16(p + 4) < 8) {
                r.status = Status::Malformed;
                return;
            }
            r.src_port = be16(p);
            r.dst_port = be16(p + 2);
            r.has_ports = true;
            break;
        }
        case Protocol::Icmp:
        case Protocol::Icmpv6:
            if (avail < 4) {
                r.status = Status::Truncated;
            }
            break;
        default:
            break;
    }
}

void parse_ipv4(ParsedPacket& r, const uint8_t* b, size_t len) {
    if (len < kIpv4MinHeader) {
        r.status = Status::Truncated;
        return;
    }
    if ((b[0] >> 4) != 4) {
        r.status = Status::Malformed;
        return;
    }
    const size_t header_len = static_cast<size_t>(b[0] & 0x0F) * 4;
    if (header_len < kIpv4MinHeader) {
        r.status = Status::Malformed;
        return;
    }
    if (len < header_len) {
        r.status = Status::Truncated;
        return;
    }
    const size_t total_len = be16(b + 2);
    if (total_len < header_len) {
        r.status = Status::Malformed;
        return;
    }

    r.ip_version = 4;
    r.ttl = b[8];
    r.ip_protocol = b[9];
    r.src = format_ipv4(b + 12);
    r.dst = format_ipv4(b + 16);
    r.protocol = classify(r.ip_protocol, false);
    r.status = Status::Ok;

    const uint16_t frag_field = be16(b + 6);
    const bool more_fragments = (frag_field & 0x2000) != 0;
    const uint16_t frag_offset = frag_field & 0x1FFF;
    r.is_fragment = more_fragments || frag_offset != 0;
    if (frag_offset != 0) {
        return;  // not the first fragment: no transport header here
    }
    const size_t end = std::min(len, total_len);  // ignore Ethernet padding past the IP length
    parse_transport(r, b + header_len, end - header_len);
}

bool is_extension_header(uint8_t next) {
    return next == 0 || next == 43 || next == 44 || next == 51 || next == 60;
}

void parse_ipv6(ParsedPacket& r, const uint8_t* b, size_t len) {
    if (len < kIpv6Header) {
        r.status = Status::Truncated;
        return;
    }
    if ((b[0] >> 4) != 6) {
        r.status = Status::Malformed;
        return;
    }
    const size_t payload_len = be16(b + 4);
    r.ip_version = 6;
    r.ttl = b[7];
    r.src = format_ipv6(b + 8);
    r.dst = format_ipv6(b + 24);

    const size_t end = std::min(len, kIpv6Header + payload_len);
    size_t pos = kIpv6Header;
    uint8_t next = b[6];
    bool non_first_fragment = false;
    int hops = 0;
    while (is_extension_header(next)) {
        if (++hops > kMaxExtensionHeaders) {
            r.status = Status::Malformed;
            return;
        }
        if (next == 44) {  // fragment header, always 8 bytes
            if (end < pos + 8) {
                r.status = Status::Truncated;
                return;
            }
            r.is_fragment = true;
            if ((be16(b + pos + 2) >> 3) != 0) {
                non_first_fragment = true;
            }
            next = b[pos];
            pos += 8;
        } else {
            if (end < pos + 2) {
                r.status = Status::Truncated;
                return;
            }
            const size_t ext_len = (next == 51) ? (static_cast<size_t>(b[pos + 1]) + 2) * 4
                                                : (static_cast<size_t>(b[pos + 1]) + 1) * 8;
            if (end < pos + ext_len) {
                r.status = Status::Truncated;
                return;
            }
            next = b[pos];
            pos += ext_len;
        }
    }

    r.ip_protocol = next;
    r.protocol = classify(next, true);
    r.status = Status::Ok;
    if (non_first_fragment) {
        return;
    }
    parse_transport(r, b + pos, end - pos);
}

}  // namespace

ParsedPacket parse_ethernet(const uint8_t* data, size_t len) {
    ParsedPacket r;
    if (data == nullptr || len < kEthernetHeader) {
        return r;  // Truncated
    }
    size_t offset = kEthernetHeader;
    uint16_t type = be16(data + 12);
    if (type == kEtherVlan || type == kEtherQinQ) {
        if (len < kEthernetHeader + kVlanTag) {
            return r;
        }
        r.vlan = true;
        type = be16(data + kEthernetHeader + 2);
        offset += kVlanTag;
    }
    r.ether_type = type;

    if (type == kEtherIpv4) {
        parse_ipv4(r, data + offset, len - offset);
    } else if (type == kEtherIpv6) {
        parse_ipv6(r, data + offset, len - offset);
    } else {
        r.status = Status::NonIp;
    }
    return r;
}

const char* protocol_name(Protocol p) {
    switch (p) {
        case Protocol::Tcp:
            return "tcp";
        case Protocol::Udp:
            return "udp";
        case Protocol::Icmp:
            return "icmp";
        case Protocol::Icmpv6:
            return "icmpv6";
        case Protocol::Other:
            return "other";
        case Protocol::None:
            break;
    }
    return "none";
}

std::string format_tcp_flags(uint8_t flags) {
    static const struct {
        uint8_t bit;
        const char* name;
    } kNames[] = {{kTcpSyn, "SYN"}, {kTcpAck, "ACK"}, {kTcpFin, "FIN"},
                  {kTcpRst, "RST"}, {kTcpPsh, "PSH"}, {kTcpUrg, "URG"}};
    std::string out;
    for (const auto& n : kNames) {
        if (flags & n.bit) {
            if (!out.empty()) {
                out += ',';
            }
            out += n.name;
        }
    }
    return out.empty() ? "none" : out;
}

}  // namespace ps
