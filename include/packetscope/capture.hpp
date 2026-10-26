#ifndef PACKETSCOPE_CAPTURE_HPP
#define PACKETSCOPE_CAPTURE_HPP

#include <csignal>
#include <ostream>
#include <string>

#include <pcap/pcap.h>

#include "packetscope/display.hpp"
#include "packetscope/stats.hpp"

namespace ps {

struct CaptureOptions {
    explicit CaptureOptions(const std::string& bpf_filter = "", long max = 100)
        : bpf(bpf_filter), max_packets(max) {}
    std::string bpf;     // optional libpcap capture filter, e.g. "tcp port 443"
    long max_packets;    // 0 means run until the file ends or the stop flag is set
};

struct CaptureResult {
    bool ok = true;
    std::string error;
};

// Reads packets from a live or offline libpcap handle, feeds them to the analyzer, and prints
// packets accepted by the display filter to out (and to log when it is not null).
// Only Ethernet captures are supported.
CaptureResult run_capture(pcap_t* handle, const CaptureOptions& options, const DisplayFilter& filter,
                          TrafficAnalyzer& analyzer, std::ostream& out, std::ostream* log,
                          const volatile std::sig_atomic_t* stop_flag = nullptr);

}  // namespace ps

#endif
