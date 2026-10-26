# PacketScope

A C++ network traffic analyzer built on libpcap. It reads packets from a live interface or a `.pcap` file, decodes Ethernet, VLAN, IPv4, IPv6, TCP, UDP, and ICMP headers, prints a line per packet, and reports traffic statistics, the busiest connections and destination ports, and possible TCP SYN port scans.

The packet decoder is a separate, bounds-checked library with no libpcap dependency, so it can be tested with hand-built byte arrays, including truncated and corrupted packets.

## Build

    cmake -S . -B build
    cmake --build build

libpcap ships with macOS. On Debian or Ubuntu, install `libpcap-dev` first.

## Usage

    ./build/packetscope -r sample.pcap -c 0          # analyze a capture file (no root needed)
    sudo ./build/packetscope tcp -i en0 -c 200       # live capture, print only TCP packets
    sudo ./build/packetscope -b "tcp port 443"       # libpcap capture filter

    python3 tools/make_sample_pcap.py                # creates sample.pcap with normal traffic and a SYN scan

| Option | Meaning |
|--------|---------|
| `[filter]` | what to print: `all`, `tcp`, `udp`, `icmp`, `icmpv6`, `ipv4`, `ipv6`, `other` (statistics always count every packet) |
| `-i <iface>` | live capture interface (default: first active non-loopback interface) |
| `-r <file>` | read a `.pcap` file instead |
| `-c <count>` | stop after this many packets (default 100, `0` = no limit) |
| `-b <bpf>` | libpcap capture filter |
| `-o <file>` | log printed packets to a file (default `capture.log`, `none` to disable) |
| `-t <n>` | port-scan alert threshold in distinct ports (default 20, `0` disables) |

Ctrl+C stops a live capture cleanly and still prints the summary.

## Example

    Packet #36 | Length: 54 bytes | Type: IPv4 | Source: 192.168.1.66:54321 | Destination: 192.168.1.10:38 | Protocol: tcp [SYN]
    ...
    ========== Traffic Summary ==========
    Total Packets: 42
    TCP Packets: 37
    UDP Packets: 3
    Non-IP Packets: 1
    ...
    ========== Possible Port Scans ==========
    ALERT: 192.168.1.66 sent SYN-only packets to many distinct ports

## Design

- `parser`: decodes a frame from raw bytes. Every read is checked against the captured length, so truncated or corrupt packets are reported (`Truncated`, `Malformed`) rather than read past the buffer. It does not cast packet bytes to structs, which avoids alignment problems and works the same on Linux and macOS.
- `stats`: counters, top connections, top ports, and the scan detector.
- `display`: the print filter and all text formatting.
- `capture`: the libpcap read loop, capture filters, and the stop flag.

## Requirements

| ID | Requirement |
|----|-------------|
| PS-001 | The parser shall extract addresses, TCP ports, flags, and TTL from IPv4 TCP packets, including packets with IP and TCP options. |
| PS-002 | The parser shall classify UDP, ICMP, and other IP protocols, and ignore Ethernet padding after the IP length. |
| PS-003 | The parser shall decode IPv6 packets, skip extension headers, and format addresses in compressed form. |
| PS-004 | The parser shall handle 802.1Q VLAN-tagged frames. |
| PS-005 | The parser shall report non-IP frames such as ARP, and a missing buffer, without error. |
| PS-006 | For a packet made only of headers, every shorter prefix shall be reported as Truncated, and no byte past the captured length shall be read. |
| PS-007 | The parser shall return a valid status and not crash on random and corrupted input. |
| PS-008 | The parser shall report impossible header values (bad IP version, header length, total length, TCP data offset, UDP length, long extension chains) as Malformed. |
| PS-009 | The parser shall not read transport ports from non-first fragments. |
| PS-010 | Statistics shall count each packet once in the correct category, including truncated, malformed, and non-IP packets. |
| PS-011 | Top-connection and top-port lists shall be ordered by count, with ties broken the same way every run. |
| PS-012 | The scan detector shall flag a source that sends SYN-only packets to at least the threshold of distinct ports, and shall not flag normal traffic, SYN-ACK replies, or a source below the threshold. |
| PS-013 | The print filter shall accept only the documented names and match packets accordingly. |
| PS-014 | Output formatting shall be correct for IPv4, IPv6, TCP flags, fragments, and error cases. |
| PS-015 | The capture loop shall read packets from a `.pcap` file and print and log them. |
| PS-016 | The print filter shall change what is printed but not what is counted. |
| PS-017 | The capture loop shall stop at the packet limit and when the stop flag is set. |
| PS-018 | The capture loop shall apply libpcap capture filters and report invalid ones. |
| PS-019 | The capture loop shall report a missing handle and non-Ethernet captures instead of failing. |

Every check in `tests/test_packetscope.cpp` is tagged with the requirement it verifies.

## Test

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build --output-on-failure

    # with AddressSanitizer and UndefinedBehaviorSanitizer
    cmake -S . -B build-san -DPACKETSCOPE_SANITIZE=ON && cmake --build build-san && ./build-san/packetscope_tests

    # with gcov coverage
    cmake -S . -B build-cov -DPACKETSCOPE_COVERAGE=ON && cmake --build build-cov && ./build-cov/packetscope_tests

## Results

- 110 checks, 0 failures, also clean under AddressSanitizer and UndefinedBehaviorSanitizer
- gcov line coverage: parser 99%, display 99%, stats 96%, capture 83% (the uncovered capture lines are live-capture error and timeout paths that a file cannot trigger)

## Limitations

IP and transport checksums are not verified. Only Ethernet captures are supported. IP fragments are not reassembled, and TCP streams are not reconstructed.
