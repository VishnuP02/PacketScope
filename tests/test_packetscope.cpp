// Requirements-based tests. Each check names the requirement (see README.md) it verifies.
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

#include "packetscope/capture.hpp"
#include "packetscope/display.hpp"
#include "packetscope/parser.hpp"
#include "packetscope/stats.hpp"

using Bytes = std::vector<uint8_t>;
using ps::kTcpAck;
using ps::kTcpSyn;

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(req, cond)                                                                \
    do {                                                                                \
        ++tests_run;                                                                    \
        if (!(cond)) {                                                                  \
            ++tests_failed;                                                             \
            std::cout << "FAIL [" << req << "] line " << __LINE__ << ": " << #cond << "\n"; \
        }                                                                               \
    } while (0)

// ---- packet builders ----------------------------------------------------------------------

static void put16(Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xFF));
}

static Bytes cat(Bytes a, const Bytes& b) {
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

static Bytes ether(uint16_t type, bool vlan = false) {
    Bytes b = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x02};
    if (vlan) {
        put16(b, 0x8100);
        put16(b, 0x0064);
    }
    put16(b, type);
    return b;
}

static Bytes tcp(uint16_t sport, uint16_t dport, uint8_t flags, uint8_t data_offset_words = 5) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    for (int i = 0; i < 8; ++i) b.push_back(0);  // sequence and acknowledgment numbers
    b.push_back(static_cast<uint8_t>(data_offset_words << 4));
    b.push_back(flags);
    for (int i = 0; i < 6; ++i) b.push_back(0);  // window, checksum, urgent pointer
    while (b.size() < static_cast<size_t>(data_offset_words) * 4) b.push_back(0);
    return b;
}

static Bytes udp(uint16_t sport, uint16_t dport, size_t payload = 0, uint16_t length_override = 0) {
    Bytes b;
    put16(b, sport);
    put16(b, dport);
    put16(b, length_override != 0 ? length_override : static_cast<uint16_t>(8 + payload));
    put16(b, 0);
    for (size_t i = 0; i < payload; ++i) b.push_back(0x55);
    return b;
}

static Bytes icmp_echo() { return Bytes{8, 0, 0, 0, 0, 1, 0, 1}; }

static Bytes ipv4(uint8_t proto, const Bytes& l4, const std::vector<uint8_t>& src = {10, 0, 0, 1},
                  const std::vector<uint8_t>& dst = {10, 0, 0, 2}, uint8_t ttl = 64,
                  uint16_t frag_field = 0, uint8_t ihl_words = 5, uint8_t version = 4) {
    Bytes b;
    b.push_back(static_cast<uint8_t>((version << 4) | ihl_words));
    b.push_back(0);
    put16(b, static_cast<uint16_t>(ihl_words * 4 + l4.size()));
    put16(b, 0);
    put16(b, frag_field);
    b.push_back(ttl);
    b.push_back(proto);
    put16(b, 0);
    for (uint8_t x : src) b.push_back(x);
    for (uint8_t x : dst) b.push_back(x);
    while (b.size() < static_cast<size_t>(ihl_words) * 4) b.push_back(0);
    return cat(b, l4);
}

static Bytes ipv6(uint8_t next, const Bytes& rest, const Bytes& src, const Bytes& dst, uint8_t hop = 60) {
    Bytes b = {0x60, 0, 0, 0};
    put16(b, static_cast<uint16_t>(rest.size()));
    b.push_back(next);
    b.push_back(hop);
    b = cat(b, src);
    b = cat(b, dst);
    return cat(b, rest);
}

static const Bytes kV6Src = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const Bytes kV6Dst = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

static Bytes frame_v4_tcp(uint8_t flags = kTcpSyn, uint16_t sport = 40000, uint16_t dport = 80,
                          const std::vector<uint8_t>& src = {10, 0, 0, 1}) {
    return cat(ether(0x0800), ipv4(6, tcp(sport, dport, flags), src));
}

static ps::ParsedPacket parse(const Bytes& b) { return ps::parse_ethernet(b.data(), b.size()); }

static ps::DisplayFilter flt(const char* name) {
    ps::DisplayFilter f;
    ps::DisplayFilter::parse(name, f);
    return f;
}

static bool valid_filter(const char* name) {
    ps::DisplayFilter f;
    return ps::DisplayFilter::parse(name, f);
}

// ---- tests --------------------------------------------------------------------------------

static void test_ipv4_tcp() {
    auto p = parse(frame_v4_tcp(kTcpSyn | kTcpAck, 40000, 443));
    CHECK("PS-001", p.status == ps::Status::Ok && p.ip_version == 4);
    CHECK("PS-001", p.src == "10.0.0.1" && p.dst == "10.0.0.2");
    CHECK("PS-001", p.protocol == ps::Protocol::Tcp && p.has_ports);
    CHECK("PS-001", p.src_port == 40000 && p.dst_port == 443);
    CHECK("PS-001", p.tcp_flags == (kTcpSyn | kTcpAck) && p.ttl == 64);
    CHECK("PS-001", ps::format_tcp_flags(p.tcp_flags) == "SYN,ACK");
    CHECK("PS-001", ps::format_tcp_flags(0) == "none");
    // IPv4 options and TCP options push the headers out; ports must still be found
    auto q = parse(cat(ether(0x0800), ipv4(6, tcp(1234, 25, kTcpAck, 8), {10, 0, 0, 1}, {10, 0, 0, 2}, 64, 0, 7)));
    CHECK("PS-001", q.status == ps::Status::Ok && q.src_port == 1234 && q.dst_port == 25);
}

static void test_ipv4_udp_icmp_other() {
    auto u = parse(cat(ether(0x0800), ipv4(17, udp(5353, 53, 12))));
    CHECK("PS-002", u.status == ps::Status::Ok && u.protocol == ps::Protocol::Udp);
    CHECK("PS-002", u.src_port == 5353 && u.dst_port == 53);
    auto i = parse(cat(ether(0x0800), ipv4(1, icmp_echo())));
    CHECK("PS-002", i.status == ps::Status::Ok && i.protocol == ps::Protocol::Icmp && !i.has_ports);
    auto o = parse(cat(ether(0x0800), ipv4(47, Bytes(8, 0))));  // GRE
    CHECK("PS-002", o.status == ps::Status::Ok && o.protocol == ps::Protocol::Other && o.ip_protocol == 47);
    // Ethernet padding after a short IP packet must not be read as transport data
    Bytes padded = cat(ether(0x0800), ipv4(1, icmp_echo()));
    padded.resize(padded.size() + 20, 0xEE);
    CHECK("PS-002", parse(padded).status == ps::Status::Ok);
}

static void test_ipv6() {
    auto t = parse(cat(ether(0x86DD), ipv6(6, tcp(5000, 22, kTcpSyn), kV6Src, kV6Dst)));
    CHECK("PS-003", t.status == ps::Status::Ok && t.ip_version == 6 && t.protocol == ps::Protocol::Tcp);
    CHECK("PS-003", t.src == "2001:db8::1" && t.dst == "2001:db8::2");
    CHECK("PS-003", t.src_port == 5000 && t.dst_port == 22 && t.ttl == 60);
    auto i6 = parse(cat(ether(0x86DD), ipv6(58, Bytes{128, 0, 0, 0, 0, 1, 0, 1}, kV6Src, kV6Dst)));
    CHECK("PS-003", i6.protocol == ps::Protocol::Icmpv6 && i6.status == ps::Status::Ok);
    // a hop-by-hop extension header sits between the IPv6 header and TCP
    Bytes hbh = {6, 0, 1, 4, 0, 0, 0, 0};
    auto e = parse(cat(ether(0x86DD), ipv6(0, cat(hbh, tcp(1, 2, kTcpAck)), kV6Src, kV6Dst)));
    CHECK("PS-003", e.status == ps::Status::Ok && e.protocol == ps::Protocol::Tcp && e.dst_port == 2);
    // address formatting corner cases
    Bytes loop(16, 0);
    loop[15] = 1;
    CHECK("PS-003", parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), loop, Bytes(16, 0)))).src == "::1");
    CHECK("PS-003", parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), loop, Bytes(16, 0)))).dst == "::");
    Bytes mixed = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x1a, 0x2b, 0xff, 0xfe, 0x3c, 0x4d, 0x5e};
    CHECK("PS-003", parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), mixed, mixed))).src == "fe80::21a:2bff:fe3c:4d5e");
    Bytes lone_zero = {0x20, 1, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6};  // a single zero group is not compressed
    CHECK("PS-003", parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), lone_zero, lone_zero))).src == "2001:0:1:2:3:4:5:6");
}

static void test_vlan_and_non_ip() {
    auto v = parse(cat(ether(0x0800, true), ipv4(6, tcp(1, 2, kTcpSyn))));
    CHECK("PS-004", v.status == ps::Status::Ok && v.vlan && v.dst_port == 2);
    auto arp = parse(cat(ether(0x0806), Bytes(28, 0)));
    CHECK("PS-005", arp.status == ps::Status::NonIp && arp.ether_type == 0x0806);
    CHECK("PS-005", ps::parse_ethernet(nullptr, 100).status == ps::Status::Truncated);
}

static void test_truncation_every_length() {
    // Packets made only of headers: every proper prefix must be reported as Truncated, and the
    // parser must never read beyond the prefix (this test is run under AddressSanitizer).
    const std::vector<Bytes> packets = {
        frame_v4_tcp(),
        cat(ether(0x0800), ipv4(17, udp(1, 2))),
        cat(ether(0x0800, true), ipv4(6, tcp(1, 2, kTcpSyn, 6))),
        cat(ether(0x86DD), ipv6(6, tcp(1, 2, kTcpSyn), kV6Src, kV6Dst)),
        cat(ether(0x86DD), ipv6(0, cat(Bytes{17, 0, 1, 4, 0, 0, 0, 0}, udp(1, 2)), kV6Src, kV6Dst)),
    };
    bool all_truncated = true;
    bool full_ok = true;
    for (const Bytes& pkt : packets) {
        for (size_t n = 0; n < pkt.size(); ++n) {
            Bytes prefix(pkt.begin(), pkt.begin() + static_cast<std::ptrdiff_t>(n));
            if (ps::parse_ethernet(prefix.data(), prefix.size()).status != ps::Status::Truncated) {
                all_truncated = false;
            }
        }
        full_ok &= (parse(pkt).status == ps::Status::Ok);
    }
    CHECK("PS-006", all_truncated);
    CHECK("PS-006", full_ok);
    // ICMP only needs its first 4 bytes (type, code, checksum)
    Bytes icmp_pkt = cat(ether(0x0800), ipv4(1, icmp_echo()));
    Bytes icmp3(icmp_pkt.begin(), icmp_pkt.begin() + 14 + 20 + 3);
    Bytes icmp4(icmp_pkt.begin(), icmp_pkt.begin() + 14 + 20 + 4);
    CHECK("PS-006", parse(icmp3).status == ps::Status::Truncated);
    CHECK("PS-006", parse(icmp4).status == ps::Status::Ok);
    // cutting only payload is fine: the headers are complete
    Bytes with_payload = cat(ether(0x0800), ipv4(17, udp(1, 2, 100)));
    with_payload.resize(with_payload.size() - 60);
    CHECK("PS-006", parse(with_payload).status == ps::Status::Ok);
}

static void test_fuzz_never_crashes() {
    // Deterministic pseudo-random input, plus single-byte corruptions of valid packets.
    uint32_t state = 12345;
    auto next = [&state]() {
        state = state * 1664525u + 1013904223u;
        return static_cast<uint8_t>(state >> 24);
    };
    bool valid_status = true;
    for (int i = 0; i < 3000; ++i) {
        Bytes b(next() % 120);
        for (auto& x : b) x = next();
        auto st = ps::parse_ethernet(b.data(), b.size()).status;
        valid_status &= (st == ps::Status::Ok || st == ps::Status::NonIp || st == ps::Status::Truncated ||
                         st == ps::Status::Malformed);
    }
    const std::vector<Bytes> seeds = {frame_v4_tcp(), cat(ether(0x86DD), ipv6(6, tcp(1, 2, kTcpSyn), kV6Src, kV6Dst))};
    for (const Bytes& seed : seeds) {
        for (size_t pos = 0; pos < seed.size(); ++pos) {
            for (int v = 0; v < 256; v += 17) {
                Bytes b = seed;
                b[pos] = static_cast<uint8_t>(v);
                auto st = ps::parse_ethernet(b.data(), b.size()).status;
                valid_status &= (st == ps::Status::Ok || st == ps::Status::NonIp ||
                                 st == ps::Status::Truncated || st == ps::Status::Malformed);
            }
        }
    }
    CHECK("PS-007", valid_status);
}

static void test_malformed_headers() {
    CHECK("PS-008", parse(cat(ether(0x0800), ipv4(6, tcp(1, 2, 0), {1, 1, 1, 1}, {2, 2, 2, 2}, 64, 0, 5, 5))).status ==
                        ps::Status::Malformed);  // IP version 5 in an IPv4 frame
    // IHL of 4 words is below the 20-byte minimum
    Bytes bad_ihl = cat(ether(0x0800), ipv4(6, tcp(1, 2, 0)));
    bad_ihl[14] = 0x44;
    CHECK("PS-008", parse(bad_ihl).status == ps::Status::Malformed);
    // total length smaller than the header
    Bytes bad_total = cat(ether(0x0800), ipv4(6, tcp(1, 2, 0)));
    bad_total[16] = 0;
    bad_total[17] = 10;
    CHECK("PS-008", parse(bad_total).status == ps::Status::Malformed);
    // TCP data offset of 2 words
    CHECK("PS-008", parse(cat(ether(0x0800), ipv4(6, tcp(1, 2, 0, 5)))).status == ps::Status::Ok);
    Bytes bad_off = cat(ether(0x0800), ipv4(6, tcp(1, 2, 0)));
    bad_off[14 + 20 + 12] = 0x20;
    CHECK("PS-008", parse(bad_off).status == ps::Status::Malformed);
    // TCP data offset claims options that are not there
    Bytes long_off = cat(ether(0x0800), ipv4(6, tcp(1, 2, 0)));
    long_off[14 + 20 + 12] = 0xF0;
    CHECK("PS-008", parse(long_off).status == ps::Status::Truncated);
    // UDP length below 8
    CHECK("PS-008", parse(cat(ether(0x0800), ipv4(17, udp(1, 2, 0, 4)))).status == ps::Status::Malformed);
    // IPv6 version nibble wrong
    Bytes v6 = cat(ether(0x86DD), ipv6(6, tcp(1, 2, 0), kV6Src, kV6Dst));
    v6[14] = 0x40;
    CHECK("PS-008", parse(v6).status == ps::Status::Malformed);
    // a chain of more than eight extension headers is rejected
    Bytes chain;
    for (int i = 0; i < 9; ++i) chain = cat(chain, Bytes{0, 0, 1, 4, 0, 0, 0, 0});
    CHECK("PS-008", parse(cat(ether(0x86DD), ipv6(0, cat(chain, tcp(1, 2, 0)), kV6Src, kV6Dst))).status ==
                        ps::Status::Malformed);
}

static void test_fragments() {
    // first fragment (more-fragments set, offset 0): ports are available
    auto first = parse(cat(ether(0x0800), ipv4(6, tcp(1, 2, kTcpAck), {10, 0, 0, 1}, {10, 0, 0, 2}, 64, 0x2000)));
    CHECK("PS-009", first.status == ps::Status::Ok && first.is_fragment && first.has_ports);
    // later fragment: payload bytes are not a transport header, so no ports
    auto later = parse(cat(ether(0x0800), ipv4(6, Bytes(30, 0xFF), {10, 0, 0, 1}, {10, 0, 0, 2}, 64, 0x00B9)));
    CHECK("PS-009", later.status == ps::Status::Ok && later.is_fragment && !later.has_ports);
    CHECK("PS-009", later.protocol == ps::Protocol::Tcp);
    // IPv6 fragment header with a non-zero offset
    Bytes frag = {6, 0, 0x00, 0x08, 0, 0, 0, 1};  // next=tcp, offset 1 (8 bytes)
    auto v6 = parse(cat(ether(0x86DD), ipv6(44, cat(frag, Bytes(30, 0xFF)), kV6Src, kV6Dst)));
    CHECK("PS-009", v6.status == ps::Status::Ok && v6.is_fragment && !v6.has_ports);
}

static void test_stats() {
    ps::TrafficAnalyzer a;
    a.record(parse(frame_v4_tcp()), 100);
    a.record(parse(cat(ether(0x0800), ipv4(17, udp(1, 2)))), 200);
    a.record(parse(cat(ether(0x0800), ipv4(1, icmp_echo()))), 60);
    a.record(parse(cat(ether(0x0800), ipv4(47, Bytes(8, 0)))), 60);
    a.record(parse(cat(ether(0x86DD), ipv6(6, tcp(1, 2, kTcpAck), kV6Src, kV6Dst))), 120);
    a.record(parse(cat(ether(0x86DD), ipv6(58, Bytes{128, 0, 0, 0, 0, 1, 0, 1}, kV6Src, kV6Dst))), 100);
    a.record(parse(cat(ether(0x0806), Bytes(28, 0))), 42);
    a.record(ps::parse_ethernet(nullptr, 0), 8);
    a.record(parse(cat(ether(0x0800), ipv4(6, tcp(1, 2, 0), {1, 1, 1, 1}, {2, 2, 2, 2}, 64, 0, 5, 7))), 70);
    const auto& s = a.stats();
    CHECK("PS-010", s.total == 9 && s.bytes == 760);
    CHECK("PS-010", s.ipv4 == 4 && s.ipv6 == 2);
    CHECK("PS-010", s.tcp == 2 && s.udp == 1 && s.icmp == 1 && s.icmpv6 == 1 && s.other == 1);
    CHECK("PS-010", s.non_ip == 1 && s.truncated == 1 && s.malformed == 1);
    CHECK("PS-010", s.average_size() > 84.4 && s.average_size() < 84.5);
    CHECK("PS-010", ps::TrafficStats{}.average_size() == 0.0);
}

static void test_top_lists() {
    ps::TrafficAnalyzer a;
    for (int i = 0; i < 3; ++i) a.record(parse(frame_v4_tcp(kTcpAck, 1000, 80, {10, 0, 0, 9})), 60);
    for (int i = 0; i < 3; ++i) a.record(parse(frame_v4_tcp(kTcpAck, 1000, 443, {10, 0, 0, 5})), 60);
    a.record(parse(frame_v4_tcp(kTcpAck, 1000, 80, {10, 0, 0, 7})), 60);
    auto conns = a.top_connections(2);
    CHECK("PS-011", conns.size() == 2);
    CHECK("PS-011", conns[0].first == "10.0.0.5 -> 10.0.0.2" && conns[0].second == 3);  // tie broken alphabetically
    CHECK("PS-011", conns[1].first == "10.0.0.9 -> 10.0.0.2" && conns[1].second == 3);
    auto ports = a.top_ports(5);
    CHECK("PS-011", ports.size() == 2 && ports[0].first == 80 && ports[0].second == 4);
    CHECK("PS-011", ports[1].first == 443 && ports[1].second == 3);
    CHECK("PS-011", ps::TrafficAnalyzer().top_connections(5).empty());
}

static void test_scan_detection() {
    ps::TrafficAnalyzer a(5);
    for (uint16_t port = 1; port <= 5; ++port) {
        a.record(parse(frame_v4_tcp(kTcpSyn, 40000, port, {10, 9, 9, 9})), 60);
    }
    // a busy but normal client: many packets to one port, and SYN-ACK replies to many ports
    for (int i = 0; i < 50; ++i) a.record(parse(frame_v4_tcp(kTcpSyn, 40000, 443, {10, 1, 1, 1})), 60);
    for (uint16_t port = 1; port <= 20; ++port) {
        a.record(parse(frame_v4_tcp(kTcpSyn | kTcpAck, 80, port, {10, 2, 2, 2})), 60);
    }
    // four distinct ports is below the threshold of five
    for (uint16_t port = 1; port <= 4; ++port) {
        a.record(parse(frame_v4_tcp(kTcpSyn, 40000, port, {10, 3, 3, 3})), 60);
    }
    auto scanners = a.suspected_scanners();
    CHECK("PS-012", scanners.size() == 1 && scanners[0] == "10.9.9.9");
    CHECK("PS-012", ps::format_scan_alerts(a).find("ALERT: 10.9.9.9") != std::string::npos);
    ps::TrafficAnalyzer none;
    CHECK("PS-012", ps::format_scan_alerts(none).empty());
    ps::TrafficAnalyzer off(0);  // threshold 0 disables detection
    for (uint16_t port = 1; port <= 30; ++port) off.record(parse(frame_v4_tcp(kTcpSyn, 1, port)), 60);
    CHECK("PS-012", off.suspected_scanners().empty());
}

static void test_filters() {
    auto tcp4 = parse(frame_v4_tcp());
    auto udp6 = parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), kV6Src, kV6Dst)));
    auto arp = parse(cat(ether(0x0806), Bytes(28, 0)));
    auto cut = ps::parse_ethernet(nullptr, 0);
    CHECK("PS-013", !valid_filter("bogus"));
    CHECK("PS-013", !valid_filter(""));
    CHECK("PS-013", valid_filter("all") && flt("all").matches(tcp4) && flt("all").matches(cut));
    CHECK("PS-013", flt("tcp").matches(tcp4) && !flt("tcp").matches(udp6));
    CHECK("PS-013", flt("udp").matches(udp6) && !flt("udp").matches(tcp4));
    CHECK("PS-013", flt("ipv4").matches(tcp4) && !flt("ipv4").matches(udp6));
    CHECK("PS-013", flt("ipv6").matches(udp6) && !flt("ipv6").matches(tcp4));
    CHECK("PS-013", flt("other").matches(arp) && flt("other").matches(cut));
    CHECK("PS-013", !flt("tcp").matches(arp) && !flt("icmp").matches(cut));
    CHECK("PS-013", flt("tcp").name() == "tcp");
}

static void test_formatting() {
    auto p = parse(frame_v4_tcp(kTcpSyn, 40000, 80));
    CHECK("PS-014", ps::format_packet_line(7, 66, p) ==
                        "Packet #7 | Length: 66 bytes | Type: IPv4 | Source: 10.0.0.1:40000 | Destination: "
                        "10.0.0.2:80 | Protocol: tcp [SYN]");
    auto v6 = parse(cat(ether(0x86DD), ipv6(17, udp(1, 2), kV6Src, kV6Dst)));
    CHECK("PS-014", ps::format_packet_line(1, 90, v6).find("Source: [2001:db8::1]:1") != std::string::npos);
    auto icmp = parse(cat(ether(0x0800), ipv4(1, icmp_echo())));
    CHECK("PS-014", ps::format_packet_line(1, 60, icmp).find("Source: 10.0.0.1 |") != std::string::npos);
    auto arp = parse(cat(ether(0x0806), Bytes(28, 0)));
    CHECK("PS-014", ps::format_packet_line(2, 42, arp).find("Non-IP packet (ethertype 0x806)") != std::string::npos);
    CHECK("PS-014", ps::format_packet_line(3, 8, ps::parse_ethernet(nullptr, 0)).find("Truncated capture") != std::string::npos);
    Bytes bad_ihl = cat(ether(0x0800), ipv4(6, tcp(1, 2, 0)));
    bad_ihl[14] = 0x44;
    CHECK("PS-014", ps::format_packet_line(4, 60, parse(bad_ihl)).find("Malformed header") != std::string::npos);
    auto frag = parse(cat(ether(0x0800), ipv4(6, tcp(1, 2, kTcpAck), {10, 0, 0, 1}, {10, 0, 0, 2}, 64, 0x2000)));
    CHECK("PS-014", ps::format_packet_line(5, 60, frag).find("(fragment)") != std::string::npos);

    ps::TrafficAnalyzer a;
    a.record(p, 100);
    const std::string summary = ps::format_summary(a, "tcp");
    CHECK("PS-014", summary.find("Total Packets: 1") != std::string::npos);
    CHECK("PS-014", summary.find("Average Packet Size: 100.0 bytes") != std::string::npos);
    CHECK("PS-014", summary.find("Display filter: tcp") != std::string::npos);
    CHECK("PS-014", ps::format_top_connections(a, 5).find("1. 10.0.0.1 -> 10.0.0.2 | Packets: 1") != std::string::npos);
    CHECK("PS-014", ps::format_top_ports(a, 5).find("1. port 80 | Packets: 1") != std::string::npos);
    ps::TrafficAnalyzer empty;
    CHECK("PS-014", ps::format_top_connections(empty, 5).find("No IP connections captured.") != std::string::npos);
    CHECK("PS-014", ps::format_top_ports(empty, 5).find("No TCP/UDP traffic captured.") != std::string::npos);
}


static void test_header_length_edges() {
    // IPv4 header length field (15 words = 60 bytes) larger than what was captured
    Bytes long_ihl = frame_v4_tcp();
    long_ihl[14] = 0x4F;
    CHECK("PS-006", parse(long_ihl).status == ps::Status::Truncated);
    // IPv6 extension header whose own length field runs past the captured bytes
    CHECK("PS-006", parse(cat(ether(0x86DD), ipv6(0, Bytes{17}, kV6Src, kV6Dst))).status == ps::Status::Truncated);
    CHECK("PS-006", parse(cat(ether(0x86DD), ipv6(0, Bytes{17, 5, 0, 0, 0, 0, 0, 0}, kV6Src, kV6Dst))).status ==
                        ps::Status::Truncated);
    // IPv6 fragment header cut short
    CHECK("PS-006", parse(cat(ether(0x86DD), ipv6(44, Bytes{6, 0, 0}, kV6Src, kV6Dst))).status == ps::Status::Truncated);
    // names used in reports
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::Tcp)) == "tcp");
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::Udp)) == "udp");
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::Icmp)) == "icmp");
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::Icmpv6)) == "icmpv6");
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::Other)) == "other");
    CHECK("PS-014", std::string(ps::protocol_name(ps::Protocol::None)) == "none");
    // asking for fewer top entries than exist
    ps::TrafficAnalyzer a;
    a.record(parse(frame_v4_tcp(kTcpAck, 1, 80)), 60);
    a.record(parse(frame_v4_tcp(kTcpAck, 1, 81)), 60);
    a.record(parse(frame_v4_tcp(kTcpAck, 1, 82)), 60);
    CHECK("PS-011", a.top_ports(2).size() == 2);
}

// ---- end-to-end through libpcap -----------------------------------------------------------

static bool write_pcap(const std::string& path, const std::vector<Bytes>& packets, int linktype = DLT_EN10MB) {
    pcap_t* dead = pcap_open_dead(linktype, 65535);
    if (dead == nullptr) return false;
    pcap_dumper_t* dumper = pcap_dump_open(dead, path.c_str());
    if (dumper == nullptr) {
        pcap_close(dead);
        return false;
    }
    for (const Bytes& pkt : packets) {
        pcap_pkthdr hdr{};
        hdr.caplen = hdr.len = static_cast<bpf_u_int32>(pkt.size());
        pcap_dump(reinterpret_cast<u_char*>(dumper), &hdr, pkt.data());
    }
    pcap_dump_close(dumper);
    pcap_close(dead);
    return true;
}

static void test_end_to_end() {
    const std::string path = "packetscope_test.pcap";
    std::vector<Bytes> packets = {
        frame_v4_tcp(kTcpSyn, 40000, 80),
        cat(ether(0x0800), ipv4(17, udp(5353, 53, 4))),
        cat(ether(0x0806), Bytes(28, 0)),
        frame_v4_tcp(kTcpAck, 40000, 80),
    };
    CHECK("PS-015", write_pcap(path, packets));
    char err[PCAP_ERRBUF_SIZE];

    {  // everything, no filter
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        CHECK("PS-015", h != nullptr);
        ps::TrafficAnalyzer a;
        std::ostringstream out, log;
        auto r = ps::run_capture(h, ps::CaptureOptions{"", 0}, flt("all"), a, out, &log);
        pcap_close(h);
        CHECK("PS-015", r.ok && a.stats().total == 4 && a.stats().tcp == 2 && a.stats().udp == 1);
        CHECK("PS-015", out.str() == log.str());
        CHECK("PS-015", out.str().find("Packet #1 |") == 0);
    }
    {  // display filter prints fewer lines but statistics still count everything
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        auto r = ps::run_capture(h, ps::CaptureOptions{"", 0}, flt("udp"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-016", r.ok && a.stats().total == 4);
        CHECK("PS-016", out.str().find("Protocol: udp") != std::string::npos && out.str().find("tcp") == std::string::npos);
    }
    {  // packet limit
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        ps::run_capture(h, ps::CaptureOptions{"", 2}, flt("all"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-017", a.stats().total == 2);
    }
    {  // capture (BPF) filter
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        auto r = ps::run_capture(h, ps::CaptureOptions{"udp", 0}, flt("all"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-018", r.ok && a.stats().total == 1 && a.stats().udp == 1);
    }
    {  // invalid BPF expression
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        auto r = ps::run_capture(h, ps::CaptureOptions{"not a valid ((filter", 0}, flt("all"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-018", !r.ok && r.error.find("invalid capture filter") == 0);
    }
    {  // stop flag set before the loop starts
        pcap_t* h = pcap_open_offline(path.c_str(), err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        volatile std::sig_atomic_t stop = 1;
        auto r = ps::run_capture(h, ps::CaptureOptions{"", 0}, flt("all"), a, out, nullptr, &stop);
        pcap_close(h);
        CHECK("PS-017", r.ok && a.stats().total == 0);
    }
    {  // null handle and non-Ethernet link type are reported, not crashed on
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        auto r = ps::run_capture(nullptr, ps::CaptureOptions{}, flt("all"), a, out, nullptr);
        CHECK("PS-019", !r.ok);
        CHECK("PS-019", write_pcap("packetscope_test_raw.pcap", {Bytes(20, 0)}, DLT_RAW));
        pcap_t* h = pcap_open_offline("packetscope_test_raw.pcap", err);
        auto r2 = ps::run_capture(h, ps::CaptureOptions{}, flt("all"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-019", !r2.ok && r2.error.find("Ethernet") != std::string::npos);
        std::remove("packetscope_test_raw.pcap");
    }
    {  // a capture file that is cut off mid-packet (snap length smaller than the headers)
        pcap_t* dead = pcap_open_dead(DLT_EN10MB, 65535);
        pcap_dumper_t* d = pcap_dump_open(dead, "packetscope_test_snap.pcap");
        Bytes full = frame_v4_tcp();
        pcap_pkthdr hdr{};
        hdr.caplen = 30;  // ends inside the IP header
        hdr.len = static_cast<bpf_u_int32>(full.size());
        pcap_dump(reinterpret_cast<u_char*>(d), &hdr, full.data());
        pcap_dump_close(d);
        pcap_close(dead);
        pcap_t* h = pcap_open_offline("packetscope_test_snap.pcap", err);
        ps::TrafficAnalyzer a;
        std::ostringstream out;
        ps::run_capture(h, ps::CaptureOptions{"", 0}, flt("all"), a, out, nullptr);
        pcap_close(h);
        CHECK("PS-006", a.stats().total == 1 && a.stats().truncated == 1 && a.stats().bytes == full.size());
        std::remove("packetscope_test_snap.pcap");
    }
    std::remove(path.c_str());
}

int main() {
    test_ipv4_tcp();
    test_ipv4_udp_icmp_other();
    test_ipv6();
    test_vlan_and_non_ip();
    test_truncation_every_length();
    test_fuzz_never_crashes();
    test_malformed_headers();
    test_fragments();
    test_stats();
    test_top_lists();
    test_scan_detection();
    test_filters();
    test_formatting();
    test_header_length_edges();
    test_end_to_end();
    std::cout << tests_run << " checks, " << tests_failed << " failed\n";
    return tests_failed == 0 ? 0 : 1;
}
